FROM quay.io/keycloak/keycloak:latest
ENV KEYCLOAK_ADMIN=admin
ENV KEYCLOAK_ADMIN_PASSWORD=admin
EXPOSE 8081
CMD ["start-dev"]
