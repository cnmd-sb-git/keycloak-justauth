docker rm -f kc_demo

docker image rmi -f boy0724/kc_demo

docker build -f ./Dockerfile -t boy0724/kc_demo .

docker run --name=kc_demo -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin boy0724/kc_demo:latest start-dev


