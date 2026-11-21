-- Security foundation: profiles and classroom membership
-- This migration is additive and intentionally keeps historical migrations untouched.

-- 1. Profiles: stop exposing every profile row to every authenticated user.
DROP POLICY IF EXISTS "Public profiles are viewable" ON public.profiles;

-- Prevent users from changing authorization and server-managed progression fields
-- through the otherwise legitimate own-profile UPDATE policy.
CREATE OR REPLACE FUNCTION public.guard_profile_sensitive_fields()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = public, pg_temp
AS $$
BEGIN
  IF auth.uid() = OLD.id
     AND NOT public.has_role(auth.uid(), 'admin'::public.app_role)
     AND (
       NEW.id IS DISTINCT FROM OLD.id
       OR NEW.email IS DISTINCT FROM OLD.email
       OR NEW.role IS DISTINCT FROM OLD.role
       OR NEW.xp IS DISTINCT FROM OLD.xp
       OR NEW.gamification_level IS DISTINCT FROM OLD.gamification_level
       OR NEW.blocked IS DISTINCT FROM OLD.blocked
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
     )
  THEN
    RAISE EXCEPTION 'Sensitive profile fields can only be changed by an administrator'
      USING ERRCODE = '42501';
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS guard_profile_sensitive_fields ON public.profiles;
CREATE TRIGGER guard_profile_sensitive_fields
BEFORE UPDATE ON public.profiles
FOR EACH ROW
EXECUTE FUNCTION public.guard_profile_sensitive_fields();

-- 2. Classes: only the class owner, enrolled members, and platform admins
-- can discover a class. The membership helper is SECURITY DEFINER to avoid
-- recursive RLS evaluation between classes and class_members.
CREATE OR REPLACE FUNCTION public.is_class_member(_class_id uuid, _user_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.class_members cm
    WHERE cm.class_id = _class_id
      AND cm.user_id = _user_id
  );
$$;

REVOKE ALL ON FUNCTION public.is_class_member(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.is_class_member(uuid, uuid) TO authenticated;

DROP POLICY IF EXISTS "Classes viewable by all authenticated" ON public.classes;
CREATE POLICY "Class owners, members and admins can view classes"
ON public.classes
FOR SELECT
TO authenticated
USING (
  teacher_id = auth.uid()
  OR public.is_class_member(id, auth.uid())
  OR public.has_role(auth.uid(), 'admin'::public.app_role)
);

DROP POLICY IF EXISTS "Teachers can create classes" ON public.classes;
DROP POLICY IF EXISTS "Teachers and admins can create classes" ON public.classes;
CREATE POLICY "Teachers and admins can create classes"
ON public.classes
FOR INSERT
TO authenticated
WITH CHECK (
  teacher_id = auth.uid()
  AND (
    public.has_role(auth.uid(), 'teacher'::public.app_role)
    OR public.has_role(auth.uid(), 'admin'::public.app_role)
  )
);

DROP POLICY IF EXISTS "Teachers can update own classes" ON public.classes;
DROP POLICY IF EXISTS "Teachers and admins can update classes" ON public.classes;
CREATE POLICY "Teachers and admins can update own classes"
ON public.classes
FOR UPDATE
TO authenticated
USING (
  (teacher_id = auth.uid() AND public.has_role(auth.uid(), 'teacher'::public.app_role))
  OR public.has_role(auth.uid(), 'admin'::public.app_role)
)
WITH CHECK (
  (teacher_id = auth.uid() AND public.has_role(auth.uid(), 'teacher'::public.app_role))
  OR public.has_role(auth.uid(), 'admin'::public.app_role)
);

DROP POLICY IF EXISTS "Teachers and admins can delete own classes" ON public.classes;
CREATE POLICY "Teachers and admins can delete own classes"
ON public.classes
FOR DELETE
TO authenticated
USING (
  (teacher_id = auth.uid() AND public.has_role(auth.uid(), 'teacher'::public.app_role))
  OR public.has_role(auth.uid(), 'admin'::public.app_role)
);

-- 3. Memberships: no direct self-enrolment by guessing a class UUID.
DROP POLICY IF EXISTS "Members can view class members" ON public.class_members;
DROP POLICY IF EXISTS "Users can join classes" ON public.class_members;
CREATE POLICY "Members and class teachers can view memberships"
ON public.class_members
FOR SELECT
TO authenticated
USING (
  user_id = auth.uid()
  OR EXISTS (
    SELECT 1
    FROM public.classes c
    WHERE c.id = class_members.class_id
      AND c.teacher_id = auth.uid()
  )
  OR public.has_role(auth.uid(), 'admin'::public.app_role)
);

-- Joining must go through the code-validation function below. The existing
-- own-membership DELETE policy remains in place so learners can leave a class.
CREATE OR REPLACE FUNCTION public.join_class_by_code(_code text)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  _user_id uuid := auth.uid();
  _class_id uuid;
BEGIN
  IF _user_id IS NULL THEN
    RAISE EXCEPTION 'Authentication required' USING ERRCODE = '42501';
  END IF;

  IF _code IS NULL OR length(trim(_code)) < 4 OR length(trim(_code)) > 10 THEN
    RAISE EXCEPTION 'Invalid invitation code' USING ERRCODE = '22023';
  END IF;

  SELECT c.id
    INTO _class_id
  FROM public.classes c
  WHERE upper(c.code) = upper(trim(_code))
  LIMIT 1;

  IF _class_id IS NULL THEN
    RAISE EXCEPTION 'Invalid invitation code' USING ERRCODE = 'P0001';
  END IF;

  INSERT INTO public.class_members (class_id, user_id)
  VALUES (_class_id, _user_id)
  ON CONFLICT (class_id, user_id) DO NOTHING;

  RETURN _class_id;
END;
$$;

REVOKE ALL ON FUNCTION public.join_class_by_code(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.join_class_by_code(text) TO authenticated;
