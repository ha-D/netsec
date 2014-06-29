from crypto import KeyParser, RSAPublicKey, RSAPrivateKey


privateKeyPem = """-----BEGIN PRIVATE KEY-----
MIICggIBADANBgkqhkiG9w0BAQEFAASCAmwwggJoAgEAAoGEAMtqw93s+Gdycf0W
7zGToReAmTCaJjeErsbA8yoOiKXp3JquWXV/8gPJSiFehai7zItHt3mZtapyvvkK
57ZOR924N31Qil+jmSAemZKkifmeiGmdPu8rFZlu+mOsVQ5+WwOQgYd8m59+mlSL
qQo43sE/SIWpuv+aeX/Xp/580vuclTT3AgMBAAECgYNrPCR3ePZW6pFG//Em7JGu
5x9a7NiayfqtUoieMj09YfTnImSMud9muZW307GYizBAeJUzqKGJcqZUebg/djMS
onyf0tSScUFhGLE8Kw3G0ovnuiNmBMn1mpsKFjqJC05YOuFYx7vtbJvgz53uiv5P
kWSHpT32Ra+f89NagMLJEa1/6QJCD3jHSOpnUuo/P1d8A5PWfWUunnd/i5Vd9S+k
5zSLv4hKfJVXKmQkU7nNA9J9o3QoJDJ39ZmDfhRqJ6xlRHm7JJX1AkINJcmuQObL
6N6hml0+8jV62dNee3ows/wmT/Y73PFBghijPF6JZr2BUPv2jbM1PFyBBVd5kiLS
3HuMQ0WKHz0HH7sCQgkzLn1DNTFurTFDGjEeZbqmwfPk5ujfZsF3FT2OV1MK/g/a
1bwVVCydHTWaoq7hUUVE5WQbZr8/8Geq8YSoRgnZSQJBQjMCS2J+tjjSwt98onTs
0qX2oMUZeiDGfCIisUjJeg6T/1b4qt2lUntyMP1KWcKUAw/iYz5uGUoQyy3t9olT
v4sCQghLofXF4dWARCQWrQO9slRqIxQv3jECOWZe0K9xkPqxdYICilG4heWinnR6
zpTDphuNwJGteP6jy2+dNa15wlEN1w==
-----END PRIVATE KEY-----"""

publicKeyPem = """-----BEGIN PUBLIC KEY-----
MIGiMA0GCSqGSIb3DQEBAQUAA4GQADCBjAKBhADLasPd7PhncnH9Fu8xk6EXgJkw
miY3hK7GwPMqDoil6dyarll1f/IDyUohXoWou8yLR7d5mbWqcr75Cue2TkfduDd9
UIpfo5kgHpmSpIn5nohpnT7vKxWZbvpjrFUOflsDkIGHfJuffppUi6kKON7BP0iF
qbr/mnl/16f+fNL7nJU09wIDAQAB
-----END PUBLIC KEY-----"""

keyParser = KeyParser()
privateKey = keyParser.parsePemPrivate(privateKeyPem)
publicKey = keyParser.parsePemPublic(publicKeyPem)



testString = "haha hoho"
enc = publicKey.publicEncrypt(testString)
dec = privateKey.privateEncrypt(enc)

assert dec == testString