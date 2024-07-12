FROM  quay.io/keycloak/keycloak:24.0.4


COPY  target/keycloak-social-24.0.4.jar /opt/keycloak/providers/


RUN /opt/keycloak/bin/kc.sh build


