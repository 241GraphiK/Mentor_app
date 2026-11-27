-- Tighten messaging, notification creation, and call-log integrity.
-- This migration is additive and does not alter historical migrations.

-- 1) Notifications are created by trusted database triggers/functions only.
DROP POLICY IF EXISTS "Authenticated users can insert notifications" ON public.notifications;
DROP POLICY IF EXISTS "System can insert notifications" ON public.notifications;
REVOKE INSERT ON TABLE public.notifications FROM authenticated;

-- 2) Participants may only change the read flag on messages sent by another participant.
-- Revoke table-level UPDATE and grant only the read column.
DROP POLICY IF EXISTS "Users can update own messages" ON public.messages;
DROP POLICY IF EXISTS "Users can update messages in own conversations" ON public.messages;
REVOKE UPDATE ON TABLE public.messages FROM authenticated;
GRANT UPDATE (read) ON TABLE public.messages TO authenticated;

CREATE POLICY "Recipients can mark messages as read"
ON public.messages
FOR UPDATE
TO authenticated
USING (
  sender_id <> auth.uid()
  AND public.is_conversation_participant(conversation_id, auth.uid())
)
WITH CHECK (
  sender_id <> auth.uid()
  AND public.is_conversation_participant(conversation_id, auth.uid())
);

-- 3) A call log must belong to a conversation containing both participants,
-- and the authenticated user must be one of those participants.
DROP POLICY IF EXISTS "Users can insert call logs" ON public.call_logs;

CREATE POLICY "Conversation participants can insert valid call logs"
ON public.call_logs
FOR INSERT
TO authenticated
WITH CHECK (
  caller_id <> receiver_id
  AND auth.uid() IN (caller_id, receiver_id)
  AND public.is_conversation_participant(conversation_id, caller_id)
  AND public.is_conversation_participant(conversation_id, receiver_id)
);
