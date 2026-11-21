-- Secure exam answer keys and server-side grading.
-- Additive migration: historical migrations remain untouched.

CREATE TABLE IF NOT EXISTS public.question_answer_keys (
  question_id uuid PRIMARY KEY REFERENCES public.questions(id) ON DELETE CASCADE,
  correct_indices jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT correct_indices_is_array CHECK (jsonb_typeof(correct_indices) = 'array')
);

ALTER TABLE public.question_answer_keys ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.question_answer_keys FROM PUBLIC, anon, authenticated;

-- Migrate existing answer keys out of the client-readable questions table.
INSERT INTO public.question_answer_keys (question_id, correct_indices)
SELECT q.id,
       COALESCE(
         (
           SELECT jsonb_agg(to_jsonb(option_row.ordinality - 1) ORDER BY option_row.ordinality)
           FROM jsonb_array_elements(q.options) WITH ORDINALITY AS option_row(value, ordinality)
           WHERE COALESCE((option_row.value->>'isCorrect')::boolean, false)
         ),
         '[]'::jsonb
       )
FROM public.questions q
ON CONFLICT (question_id) DO NOTHING;

-- Remove correctness flags from all publicly readable question options.
UPDATE public.questions q
SET options = COALESCE(
  (
    SELECT jsonb_agg(option_row.value - 'isCorrect' ORDER BY option_row.ordinality)
    FROM jsonb_array_elements(q.options) WITH ORDINALITY AS option_row(value, ordinality)
  ),
  '[]'::jsonb
);

-- Only a trusted server-side function may create attempts and grades.
DROP POLICY IF EXISTS "Users can insert own attempts" ON public.quiz_attempts;
REVOKE INSERT, UPDATE, DELETE ON public.quiz_attempts FROM anon, authenticated;

CREATE OR REPLACE FUNCTION public.submit_quiz_attempt(_quiz_id uuid, _answers jsonb)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  _user_id uuid := auth.uid();
  _question record;
  _selected jsonb;
  _correct jsonb;
  _option_count integer;
  _earned integer := 0;
  _total integer := 0;
  _percentage integer := 0;
  _review jsonb := '[]'::jsonb;
  _question_review jsonb;
  _xp integer := 0;
  _difficulty text;
  _attempt_id uuid;
BEGIN
  IF _user_id IS NULL THEN
    RAISE EXCEPTION 'Authentication required' USING ERRCODE = '42501';
  END IF;
  IF _answers IS NULL OR jsonb_typeof(_answers) <> 'object' THEN
    RAISE EXCEPTION 'Invalid answer payload' USING ERRCODE = '22023';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM public.quizzes q WHERE q.id = _quiz_id) THEN
    RAISE EXCEPTION 'Quiz not found' USING ERRCODE = 'P0002';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM jsonb_object_keys(_answers) AS submitted_key(key)
    WHERE NOT EXISTS (
      SELECT 1 FROM public.questions q
      WHERE q.quiz_id = _quiz_id AND q.id::text = submitted_key.key
    )
  ) THEN
    RAISE EXCEPTION 'Answer payload contains unknown question IDs' USING ERRCODE = '22023';
  END IF;

  SELECT difficulty INTO _difficulty FROM public.quizzes WHERE id = _quiz_id;

  FOR _question IN
    SELECT q.id, q.text, q.type, q.points, q.explanation, q.options,
           k.correct_indices
    FROM public.questions q
    JOIN public.question_answer_keys k ON k.question_id = q.id
    WHERE q.quiz_id = _quiz_id
    ORDER BY q.id
  LOOP
    _total := _total + GREATEST(_question.points, 0);
    _selected := COALESCE(_answers -> _question.id::text, '[]'::jsonb);

    IF jsonb_typeof(_selected) <> 'array' THEN
      RAISE EXCEPTION 'Invalid answer format' USING ERRCODE = '22023';
    END IF;

    SELECT jsonb_array_length(_question.options) INTO _option_count;
    IF EXISTS (
      SELECT 1
      FROM jsonb_array_elements(_selected) AS picked(value)
      WHERE jsonb_typeof(picked.value) <> 'number'
         OR (picked.value::text)::numeric <> trunc((picked.value::text)::numeric)
         OR (picked.value::text)::numeric < 0
         OR (picked.value::text)::numeric >= _option_count
    ) THEN
      RAISE EXCEPTION 'Answer contains an invalid option index' USING ERRCODE = '22023';
    END IF;

    IF (SELECT count(*) FROM jsonb_array_elements(_selected)) <>
       (SELECT count(DISTINCT value) FROM jsonb_array_elements(_selected))
    THEN
      RAISE EXCEPTION 'Duplicate option index' USING ERRCODE = '22023';
    END IF;

    IF _question.type = 'single' AND jsonb_array_length(_selected) > 1 THEN
      RAISE EXCEPTION 'Only one option may be selected' USING ERRCODE = '22023';
    END IF;

    _correct := _question.correct_indices;
    IF (
      SELECT COALESCE(array_agg(value::integer ORDER BY value::integer), ARRAY[]::integer[])
      FROM jsonb_array_elements_text(_selected)
    ) = (
      SELECT COALESCE(array_agg(value::integer ORDER BY value::integer), ARRAY[]::integer[])
      FROM jsonb_array_elements_text(_correct)
    ) THEN
      _earned := _earned + GREATEST(_question.points, 0);
    END IF;

    SELECT COALESCE(jsonb_agg(
      jsonb_build_object(
        'text', option_row.value->>'text',
        'isCorrect', EXISTS (
          SELECT 1 FROM jsonb_array_elements_text(_correct) AS ci(value)
          WHERE ci.value = (option_row.ordinality - 1)::text
        ),
        'selected', EXISTS (
          SELECT 1 FROM jsonb_array_elements_text(_selected) AS si(value)
          WHERE si.value = (option_row.ordinality - 1)::text
        )
      ) ORDER BY option_row.ordinality
    ), '[]'::jsonb)
    INTO _question_review
    FROM jsonb_array_elements(_question.options) WITH ORDINALITY AS option_row(value, ordinality);

    _review := _review || jsonb_build_array(jsonb_build_object(
      'questionId', _question.id,
      'text', _question.text,
      'explanation', _question.explanation,
      'points', _question.points,
      'options', _question_review,
      'correctIndices', _correct,
      'selectedIndices', _selected
    ));
  END LOOP;

  IF _total = 0 THEN
    RAISE EXCEPTION 'This quiz has no scorable questions' USING ERRCODE = '22023';
  END IF;

  _percentage := round((_earned::numeric / _total::numeric) * 100)::integer;

  INSERT INTO public.quiz_attempts (quiz_id, user_id, score, max_score, answers)
  VALUES (_quiz_id, _user_id, _earned, _total, _answers)
  RETURNING id INTO _attempt_id;

  -- XP is awarded only after successful server-side grading.
  _xp := round((10 + round(_percentage::numeric / 10)) *
    CASE WHEN _difficulty = 'hard' THEN 2
         WHEN _difficulty = 'medium' THEN 1.5
         ELSE 1 END)::integer;

  INSERT INTO public.xp_transactions (user_id, amount, reason)
  VALUES (_user_id, _xp, 'Quiz completed: ' || _quiz_id::text);

  UPDATE public.profiles
  SET xp = xp + _xp,
      gamification_level = GREATEST(1, ((xp + _xp) / 100) + 1)
  WHERE id = _user_id;

  RETURN jsonb_build_object(
    'attemptId', _attempt_id,
    'score', _earned,
    'maxScore', _total,
    'percentage', _percentage,
    'xpAwarded', _xp,
    'review', _review
  );
END;
$$;

REVOKE ALL ON FUNCTION public.submit_quiz_attempt(uuid, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.submit_quiz_attempt(uuid, jsonb) TO authenticated;

-- Secure, atomic teacher quiz creation; answer keys never enter the public questions row.
CREATE OR REPLACE FUNCTION public.create_quiz_with_questions(
  _module_id uuid,
  _title text,
  _description text,
  _difficulty text,
  _duration integer,
  _questions jsonb
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  _user_id uuid := auth.uid();
  _quiz_id uuid;
  _item jsonb;
  _options jsonb;
  _key jsonb;
  _question_id uuid;
  _type text;
  _points integer;
BEGIN
  IF _user_id IS NULL THEN
    RAISE EXCEPTION 'Authentication required' USING ERRCODE = '42501';
  END IF;
  IF NOT (
    public.has_role(_user_id, 'teacher'::public.app_role)
    OR public.has_role(_user_id, 'admin'::public.app_role)
  ) THEN
    RAISE EXCEPTION 'Teacher role required' USING ERRCODE = '42501';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM public.modules m
    WHERE m.id = _module_id
      AND (m.teacher_id = _user_id OR public.has_role(_user_id, 'admin'::public.app_role))
  ) THEN
    RAISE EXCEPTION 'Module not found or not authorized' USING ERRCODE = '42501';
  END IF;
  IF length(trim(COALESCE(_title, ''))) = 0 OR length(_title) > 200 THEN
    RAISE EXCEPTION 'Invalid quiz title' USING ERRCODE = '22023';
  END IF;
  IF _duration < 1 OR _duration > 300 THEN
    RAISE EXCEPTION 'Invalid quiz duration' USING ERRCODE = '22023';
  END IF;
  IF _difficulty NOT IN ('easy', 'medium', 'hard') THEN
    RAISE EXCEPTION 'Invalid quiz difficulty' USING ERRCODE = '22023';
  END IF;
  IF _questions IS NULL
     OR jsonb_typeof(_questions) <> 'array'
     OR jsonb_array_length(_questions) < 1
     OR jsonb_array_length(_questions) > 100 THEN
    RAISE EXCEPTION 'Invalid question list' USING ERRCODE = '22023';
  END IF;

  INSERT INTO public.quizzes (module_id, title, description, difficulty, duration)
  VALUES (_module_id, trim(_title), COALESCE(_description, ''), _difficulty, _duration)
  RETURNING id INTO _quiz_id;

  FOR _item IN SELECT value FROM jsonb_array_elements(_questions)
  LOOP
    IF length(trim(COALESCE(_item->>'text', ''))) = 0 THEN
      RAISE EXCEPTION 'Question text is required' USING ERRCODE = '22023';
    END IF;
    _type := COALESCE(_item->>'type', 'single');
    IF _type NOT IN ('single', 'multiple') THEN
      RAISE EXCEPTION 'Unsupported question type' USING ERRCODE = '22023';
    END IF;
    IF COALESCE(_item->>'difficulty', 'medium') NOT IN ('easy', 'medium', 'hard') THEN
      RAISE EXCEPTION 'Invalid question difficulty' USING ERRCODE = '22023';
    END IF;
    _points := COALESCE((_item->>'points')::integer, 1);
    IF _points < 1 OR _points > 100 THEN
      RAISE EXCEPTION 'Invalid question points' USING ERRCODE = '22023';
    END IF;
    _options := COALESCE(_item->'options', '[]'::jsonb);
    IF jsonb_typeof(_options) <> 'array' OR jsonb_array_length(_options) < 2 OR jsonb_array_length(_options) > 10 THEN
      RAISE EXCEPTION 'Each question must have 2 to 10 options' USING ERRCODE = '22023';
    END IF;
    SELECT COALESCE(jsonb_agg(to_jsonb(option_row.ordinality - 1) ORDER BY option_row.ordinality)
      FILTER (WHERE COALESCE((option_row.value->>'isCorrect')::boolean, false)), '[]'::jsonb)
    INTO _key
    FROM jsonb_array_elements(_options) WITH ORDINALITY AS option_row(value, ordinality);
    IF jsonb_array_length(_key) = 0 THEN
      RAISE EXCEPTION 'Each question needs at least one correct answer' USING ERRCODE = '22023';
    END IF;
    IF _type = 'single' AND jsonb_array_length(_key) <> 1 THEN
      RAISE EXCEPTION 'Single-choice questions must have exactly one correct answer' USING ERRCODE = '22023';
    END IF;

    INSERT INTO public.questions (quiz_id, text, type, points, difficulty, explanation, options)
    VALUES (
      _quiz_id,
      trim(_item->>'text'),
      _type,
      _points,
      COALESCE(_item->>'difficulty', 'medium'),
      COALESCE(_item->>'explanation', ''),
      (SELECT COALESCE(jsonb_agg(option_row.value - 'isCorrect' ORDER BY option_row.ordinality), '[]'::jsonb)
       FROM jsonb_array_elements(_options) WITH ORDINALITY AS option_row(value, ordinality))
    )
    RETURNING id INTO _question_id;

    INSERT INTO public.question_answer_keys (question_id, correct_indices)
    VALUES (_question_id, _key);
  END LOOP;

  RETURN _quiz_id;
END;
$$;

REVOKE ALL ON FUNCTION public.create_quiz_with_questions(uuid, text, text, text, integer, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.create_quiz_with_questions(uuid, text, text, text, integer, jsonb) TO authenticated;

-- Prevent alternate direct-write paths from reintroducing answer flags.
DROP POLICY IF EXISTS "Teachers can insert questions" ON public.questions;
DROP POLICY IF EXISTS "Teachers can update questions" ON public.questions;
DROP POLICY IF EXISTS "Teachers can delete questions" ON public.questions;
REVOKE INSERT, UPDATE, DELETE ON public.questions FROM anon, authenticated;
