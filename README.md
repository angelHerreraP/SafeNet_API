# FastAPI Template

# SafeNet Academy API

API RESTful para la gestión de usuarios, módulos, retos, progreso, feedback y certificaciones, lista para producción.

## Requisitos
- Python 3.10+
- PostgreSQL

## Instalación

1. Clona el repositorio y entra a la carpeta:

```sh
cd fastapi-template
```

2. Instala las dependencias:

```sh
pip install -r requirements.txt
```

3. Copia y configura tu archivo `.env`:

```sh
cp .env.example .env
# Edita .env con tus credenciales
```

4. Crea las tablas en la base de datos (se hace automáticamente al iniciar la API).

5. Ejecuta el servidor:

```sh
uvicorn main:app --reload
```

6. Accede a la documentación interactiva en [http://localhost:8000/docs](http://localhost:8000/docs)

## Endpoints principales
- `/usuarios/` CRUD de usuarios
- `/modulos/` CRUD de módulos
- `/retos/` CRUD de retos
- `/progreso/` CRUD de progreso de usuario
- `/feedback/` CRUD de feedback
- `/certificaciones/` CRUD de certificaciones
- `/token` Login y autenticación JWT

## Notas
- Cambia el `SECRET_KEY` en tu `.env` para producción.
- El primer usuario se puede crear sin autenticación, luego los endpoints protegidos requieren JWT.
- Puedes usar herramientas como [Postman](https://www.postman.com/) o la documentación Swagger para probar la API.

---

¡Tu API está lista para usarse!
This sample repo contains the recommended structure for a Python FastAPI project. In this sample, we use `fastapi` to build a web application and the `pytest` to run tests.

For a more in-depth tutorial, see our [Fast API tutorial](https://code.visualstudio.com/docs/python/tutorial-fastapi).

The code in this repo aims to follow Python style guidelines as outlined in [PEP 8](https://peps.python.org/pep-0008/).

## Set up instructions

This sample makes use of Dev Containers, in order to leverage this setup, make sure you have [Docker installed](https://www.docker.com/products/docker-desktop).

To successfully run this example, we recommend the following VS Code extensions:

- [Dev Containers](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)
- [Python](https://marketplace.visualstudio.com/items?itemName=ms-python.python)
- [Python Debugger](https://marketplace.visualstudio.com/items?itemName=ms-python.debugpy)
- [Pylance](https://marketplace.visualstudio.com/items?itemName=ms-python.vscode-pylance) 

In addition to these extension there a few settings that are also useful to enable. You can enable to following settings by opening the Settings editor (`Ctrl+,`) and searching for the following settings:

- Python > Analysis > **Type Checking Mode** : `basic`
- Python > Analysis > Inlay Hints: **Function Return Types** : `enable`
- Python > Analysis > Inlay Hints: **Variable Types** : `enable`

## Running the sample
- Open the template folder in VS Code (**File** > **Open Folder...**)
- Open the Command Palette in VS Code (**View > Command Palette...**) and run the **Dev Container: Reopen in Container** command.
- Run the app using the Run and Debug view or by pressing `F5`
- `Ctrl + click` on the URL that shows up on the terminal to open the running application 
- Test the API functionality by navigating to `/docs` URL to view the Swagger UI
- Configure your Python test in the Test Panel or by triggering the **Python: Configure Tests** command from the Command Palette
- Run tests in the Test Panel or by clicking the Play Button next to the individual tests in the `test_main.py` file
