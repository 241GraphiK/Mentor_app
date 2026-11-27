-- Make uploaded course resources and message attachments private.
-- Object paths are persisted in the database; clients receive short-lived signed URLs.

-- Ensure both buckets exist and are private.
INSERT INTO storage.buckets (id, name, public)
VALUES
  ('message-attachments', 'message-attachments', false),
  ('course-resources', 'course-resources', false)
ON CONFLICT (id) DO UPDATE SET public = false;

-- Migrate legacy public URLs to their bucket-relative object paths.
UPDATE public.messages
SET attachment_url = substring(attachment_url FROM '/storage/v1/object/public/message-attachments/(.*)$')
WHERE attachment_url LIKE '%/storage/v1/object/public/message-attachments/%';

UPDATE public.resources
SET url = substring(url FROM '/storage/v1/object/public/course-resources/(.*)$')
WHERE url LIKE '%/storage/v1/object/public/course-resources/%';

-- Remove the overly broad legacy message attachment policies.
DROP POLICY IF EXISTS "Authenticated users can upload message attachments" ON storage.objects;
DROP POLICY IF EXISTS "Anyone can view message attachments" ON storage.objects;
DROP POLICY IF EXISTS "Users can delete own message attachments" ON storage.objects;

-- Message attachments: only a conversation participant can read an object.
-- Uploads and deletions are restricted to the authenticated sender's folder.
CREATE POLICY "Conversation participants upload own message attachments"
ON storage.objects FOR INSERT TO authenticated
WITH CHECK (
  bucket_id = 'message-attachments'
  AND (storage.foldername(name))[1] = auth.uid()::text
  AND public.is_conversation_participant(
    (storage.foldername(name))[2]::uuid,
    auth.uid()
  )
);

CREATE POLICY "Conversation participants read message attachments"
ON storage.objects FOR SELECT TO authenticated
USING (
  bucket_id = 'message-attachments'
  AND (
    (storage.foldername(name))[1] = auth.uid()::text
    OR EXISTS (
      SELECT 1
      FROM public.conversation_participants cp
      WHERE cp.conversation_id::text = (storage.foldername(name))[2]
        AND cp.user_id = auth.uid()
    )
  )
);

CREATE POLICY "Users delete own message attachments"
ON storage.objects FOR DELETE TO authenticated
USING (
  bucket_id = 'message-attachments'
  AND (storage.foldername(name))[1] = auth.uid()::text
);

-- Course resources use {course_id}/{object_name} paths.
-- Teachers who own the module may upload/delete; module-class members may read.
CREATE POLICY "Course teachers upload resources"
ON storage.objects FOR INSERT TO authenticated
WITH CHECK (
  bucket_id = 'course-resources'
  AND EXISTS (
    SELECT 1
    FROM public.courses c
    JOIN public.modules m ON m.id = c.module_id
    WHERE c.id::text = (storage.foldername(name))[1]
      AND m.teacher_id = auth.uid()
  )
);

CREATE POLICY "Authorized users read course resources"
ON storage.objects FOR SELECT TO authenticated
USING (
  bucket_id = 'course-resources'
  AND EXISTS (
    SELECT 1
    FROM public.courses c
    JOIN public.modules m ON m.id = c.module_id
    WHERE c.id::text = (storage.foldername(name))[1]
      AND (
        m.teacher_id = auth.uid()
        OR EXISTS (
          SELECT 1
          FROM public.class_modules cm
          JOIN public.class_members member ON member.class_id = cm.class_id
          WHERE cm.module_id = m.id
            AND member.user_id = auth.uid()
        )
      )
  )
);

CREATE POLICY "Course teachers delete resources"
ON storage.objects FOR DELETE TO authenticated
USING (
  bucket_id = 'course-resources'
  AND EXISTS (
    SELECT 1
    FROM public.courses c
    JOIN public.modules m ON m.id = c.module_id
    WHERE c.id::text = (storage.foldername(name))[1]
      AND m.teacher_id = auth.uid()
  )
);
