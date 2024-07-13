#FROM  quay.io/keycloak/keycloak:24.0.4
#
#COPY  target/keycloak-social-24.0.4-jar-with-dependencies.jar /opt/keycloak/providers/
FROM  quay.io/keycloak/keycloak:24.0.4

COPY  target/keycloak-social-24.0.4-jar-with-dependencies.jar /opt/keycloak/providers/


RUN /opt/keycloak/bin/kc.sh build


