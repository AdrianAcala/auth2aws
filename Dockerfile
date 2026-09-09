FROM gcr.io/distroless/static-debian11
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/saml2aws /
ENTRYPOINT ["/saml2aws"]
