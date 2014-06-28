if [ $# -ne 1 ]; then
	echo "usage: ./client <client-number>"
	exit 1
fi
echo "Starting Client $1..."

python src/app.py client --config config.json data/client/config.json --private-key-file data/client/client$1.key