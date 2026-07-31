# syntax=docker/dockerfile:1.7
FROM mitmproxy/mitmproxy:12.2.3@sha256:68afa70d7b6ac9d269b88f88534f9ffceb363b4ce31703a78702341fba82e831

USER root
COPY containers/egress_policy.py /opt/skillsissue/egress_policy.py
COPY containers/egress_capture.py /opt/skillsissue/egress_capture.py
RUN chmod 0444 /opt/skillsissue/egress_policy.py /opt/skillsissue/egress_capture.py \
    && mkdir -p /var/empty /run/evidence /run/mitmproxy \
    && chown 65532:65532 /var/empty /run/evidence /run/mitmproxy

USER 65532:65532
WORKDIR /var/empty
ENV HOME=/var/empty \
    PYTHONPATH=/opt/skillsissue
STOPSIGNAL SIGTERM
ENTRYPOINT ["mitmdump"]
CMD ["--mode", "regular@0.0.0.0:8080", "--set", "confdir=/run/mitmproxy", "--set", "anticache=true", "--set", "anticomp=true", "--set", "body_size_limit=16m", "--set", "connection_strategy=lazy", "--set", "onboarding=false", "--set", "rawtcp=false", "--set", "websocket=false", "--set", "http2=false", "--set", "http3=false", "--set", "keep_alt_svc_header=false", "--set", "ssl_insecure=false", "--set", "termlog_verbosity=warn", "--scripts", "/opt/skillsissue/egress_capture.py"]
