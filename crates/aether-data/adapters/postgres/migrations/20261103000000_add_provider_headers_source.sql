ALTER TABLE public.usage_http_audits
    ADD COLUMN IF NOT EXISTS provider_headers_source varchar(16);

ALTER TABLE public.usage_http_audits
    ALTER COLUMN provider_headers_source SET DEFAULT 'local';

UPDATE public.usage_http_audits
SET provider_headers_source = CASE
    WHEN provider_request_headers IS NULL THEN NULL
    ELSE 'local'
END
WHERE provider_headers_source IS NULL;

COMMENT ON COLUMN public.usage_http_audits.provider_headers_source IS
    '来源：upstream_echo=Go 侧回执；local=AE 本地构造/回退';
