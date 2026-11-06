-- Revert the extra provenance column: the relay body override replaces
-- provider_request_body_ref in place and does not need a second field.
ALTER TABLE public.usage_http_audits
    DROP COLUMN IF EXISTS provider_body_source;
