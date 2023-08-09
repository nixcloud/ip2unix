{ pkgs, ip2unix, ... }:

pkgs.runCommand "mariadb-php-abstract" {
  nativeBuildInputs = [ ip2unix pkgs.mariadb pkgs.php pkgs.netcat-openbsd ];
  phpScript = pkgs.writeText "testscript.php" ''
    <?php declare(strict_types=1);
    $db = new PDO('mysql:dbname=sometestdb;user=root;unix_socket=/foo/bar');
    $data = $db->query('SELECT * FROM testtable;')->fetchAll();
    if (($data[0]['id'] ?? null) !== 666)
      throw new Exception('Invalid data: '.print_r($data, true));
  '';
} ''
  mysql_install_db \
    --datadir="$PWD/db" \
    --skip-name-resolve \
    --auth-root-authentication-method=normal

  mariadbd \
    --datadir="$PWD/db" \
    --skip-networking \
    --innodb-use-native-aio=0 \
    --socket=@someabstract &

  while ! nc -zU @someabstract &> /dev/null; do sleep 1; done

  MYSQL_UNIX_PORT=@someabstract mysql -uroot <<EOF
  CREATE DATABASE sometestdb;
  CONNECT sometestdb;
  CREATE TABLE testtable (id BIGINT);
  INSERT INTO testtable VALUES(666);
  EOF

  ip2unix -r from-unix=/foo/bar,abstract=someabstract php "$phpScript"

  touch "$out"
''
