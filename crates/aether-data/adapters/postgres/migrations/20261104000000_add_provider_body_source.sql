ALTER TABLE public.usage_http_audits
    ADD COLUMN IF NOT EXISTS provider_body_source varchar(16);

ALTER TABLE public.usage_http_audits
    ALTER COLUMN provider_body_source SET DEFAULT 'local';

UPDATE public.usage_http_audits
SET provider_body_source = CASE
    WHEN provider_request_body_ref IS NULL THEN NULL
    ELSE 'local'
END
WHERE provider_body_source IS NULL;

COMMENT ON COLUMN public.usage_http_audits.provider_body_source IS
    '来源：upstream_echo=Go 侧回执覆盖；local=AE 本地构造（回退）';
