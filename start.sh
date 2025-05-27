source venv/bin/activate

export SECRET="vdfisvbdfvbh554654615656dfbdfb4n=044m5"
export JWT_NAME=sl_jwt
export NEXTCLOUD_URL="https://nextcloud.sphericallife.ru/ocs/v1.php/cloud/user"
export TOKEN_DURATION_SEC=84600
export DOMAIN=sphericallife.ru

sanic app.server:app -H 127.0.0.1 -p 8090
