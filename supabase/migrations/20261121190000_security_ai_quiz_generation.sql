-- Per-user quota for AI quiz generation.
CREATE TABLE IF NOT EXISTS public.ai_quiz_generation_usage (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ai_quiz_generation_usage_user_created_idx
ON public.ai_quiz_generation_usage (user_id, created_at DESC);

ALTER TABLE public.ai_quiz_generation_usage ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.ai_quiz_generation_usage FROM PUBLIC, anon, authenticated;

CREATE OR REPLACE FUNCTION public.consume_ai_quiz_generation_quota()
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  _user_id uuid := auth.uid();
  _recent_count integer;
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

  -- Serialize quota checks for this user to prevent concurrent requests
  -- from bypassing the hourly limit.
  PERFORM pg_advisory_xact_lock(hashtextextended(_user_id::text || ':ai-quiz-generation', 0));

  SELECT count(*)::integer
  INTO _recent_count
  FROM public.ai_quiz_generation_usage
  WHERE user_id = _user_id
    AND created_at >= now() - interval '1 hour';

  IF _recent_count >= 10 THEN
    RETURN false;
  END IF;

  INSERT INTO public.ai_quiz_generation_usage (user_id)
  VALUES (_user_id);

  RETURN true;
END;
$$;

REVOKE ALL ON FUNCTION public.consume_ai_quiz_generation_quota() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.consume_ai_quiz_generation_quota() TO authenticated;
