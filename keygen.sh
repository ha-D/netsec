
if [ $# -ne 1 ]; then
	echo "usage: ./keygen.sh <name>"
	exit 1
fi

openssl req -x509 -nodes -days 365 -newkey rsa:1048 -keyout $1.key -out $1.pem
openssl rsa -in $1.key -pubout > $1.pub
