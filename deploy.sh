sudo make docker
sudo docker run -p 4433:4433 --rm -it -v /home/debian/Code/kratos/contrib/quickstart/kratos/email-password:/etc/config/kratos oryd/kratos:latest serve --dev -c /etc/config/kratos/kratos.yml