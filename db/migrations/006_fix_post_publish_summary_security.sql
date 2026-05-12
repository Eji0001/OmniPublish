-- Make post_publish_summary respect caller permissions and RLS.
ALTER VIEW public.post_publish_summary SET (security_invoker = true);
