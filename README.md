# Wazuh to DefectDojo Integration

Integración sencilla para enviar las vulnerabilidades detectadas por **Wazuh** hacia **DefectDojo**.

El script consulta el índice de vulnerabilidades del **Wazuh Indexer**, transforma los resultados y los envía mediante la API de DefectDojo.

---
IMPORTANTE : No hace falta instalar nada dentro de DefectDojo: el script se instala y se ejecuta en la máquina donde está Wazuh.
---

# Requisitos

Antes de comenzar, se necesita:

* Una instalación de Wazuh All-in-One o una máquina con acceso al Wazuh Indexer.
* DefectDojo instalado y funcionando.
* Una API Key de DefectDojo.
* Un Engagement creado en DefectDojo.
* Acceso como `root` o mediante `sudo`.
* Los programas `curl`, `jq` y `git`.
---

## EMPECEMOS :

# Instalar dependencias en Wazuh en Debian o Ubumtu
sudo apt install -y git curl jq

# Descargar el proyecto
sudo mkdir -p /opt

cd /opt

sudo git clone https://github.com/NahuelSerantes/wazuh-defectdojo-integration.git

cd wazuh-defectdojo-integration

# Configurar credenciales de Wazuh
sudo cp config/netrc.example /root/.netrc
sudo nano /root/.netrc
sudo chown root:root /root/.netrc
sudo chmod 600 /root/.netrc

# Configurar DefectDojo
sudo cp config/wazuh-defectdojo.env.example /etc/wazuh-defectdojo.env
sudo nano /etc/wazuh-defectdojo.env
sudo chown root:root /etc/wazuh-defectdojo.env
sudo chmod 600 /etc/wazuh-defectdojo.env

# Instalar el script
sudo install -o root -g root -m 700 \
  scripts/wazuh-to-defectdojo.sh \
  /usr/local/bin/wazuh-to-defectdojo.sh


  # NOTAS DE APRENDIZAJE :

## ¿Qué es el archivo `.netrc`?

`.netrc` es un archivo utilizado por programas como `curl` para guardar credenciales.

En este proyecto se utiliza para guardar el usuario y la contraseña del Wazuh Indexer.

En lugar de escribir esto dentro del script:

```bash
curl -u admin:CONTRASEÑA https://localhost:9200
```

El usuario y la contraseña se guardan en:

```text
/root/.netrc
```

De esta manera:

* La contraseña no queda escrita dentro del script.
* La contraseña no aparece directamente en los comandos.
* El script puede autenticarse automáticamente.
* Las credenciales quedan separadas del código publicado en GitHub.

> `.netrc` sigue siendo un archivo de texto. Por eso debe tener permisos que permitan leerlo solamente al usuario `root`.

---
# Licencia

Este proyecto se distribuye bajo la licencia MIT.

Se permite utilizarlo, modificarlo y distribuirlo respetando los términos de dicha licencia.
