# ModelHub: ¿por dónde empezamos?

ModelHub distribuye modelos firmados a cámaras con inferencia local. Tiene cinco
lugares donde usa criptografía. 

Son analistas de seguridad e infraestructura. 

El objetivo es llegar a un plan que se pueda defender, y descubrir con qué se choca la migración cuando se
intenta de verdad.

## Cómo trabajamos

**1. Buscar.** Encontrá dónde usa criptografía este servicio. Llená `inventory/inventario.csv`: qué primitiva, qué la rompe (¿Grover o Shor?), con qué se reemplaza, qué dato protege y cuánto tiempo tiene que seguir
protegido.

**2. Ordenar.** Poné los cinco componentes en orden de urgencia. Supongan que
en el próximo release sólo se migran **dos componentes**.

**3. Migrar.** Agarren el primero de su lista y migrenlo. Corran `bench.py` antes y
después y comparen.

**4. Escribir.** Media carilla en `PLAN.md`:
- El orden de los cinco, una línea de justificación cada uno.
- Qué queda afuera de los dos migrados, y cómo mitigan ese riesgo mientras tanto.

## Para la puesta en común

Cada pareja trae tres cosas:
- Su orden.
- Con qué dificultades se encontraron.
- Sus números del bench.

## Extra, si terminan antes

Migrar tiene un costo, y a veces la excusa para no migrar es "esto todavía es seguro".
`forensics/` tiene dos firmas de dos releases distintos de ModelHub. El servidor que
las generó cometió un error de implementación.

Recuperá la clave privada de firma a partir de esas dos firmas. Con ella, firmá un
modelo con backdoor y pasáselo a un dispositivo: `verify_backdoor.py` los ayuda con la
última parte.

Pista: miren el valor `r` de las dos firmas antes de escribir una sola línea.

Esto no es criptografía cuántica. Es un error de uso clásico que rompe ECDSA. 

## Lo que NO es el trabajo

Implementar primitivas criptográficas a mano. 

## Antes de empezar

Abrir pq.cloudflareresearch.com desde la red de la facultad y mirá qué negocia el
navegador (DevTools → Security → grupo de intercambio de claves). 

---

## Setup

Python 3.11+ recomendado (funciona con 3.9+). Necesario `cryptography>=48`, que trae
ML-KEM y ML-DSA.

```bash
cd modelhub
python3 -m venv .venv
source .venv/bin/activate          # en Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Correr los tests

```bash
python -m pytest -q
```

Al arrancar, **todos pasan**.

### Correr el benchmark

```bash
python bench.py
```

Compara el handshake clásico (X25519) contra el post-cuántico (ML-KEM-768) en tu
máquina: latencia promedio y bytes en el cable. 

### El material del ataque (extra)

```bash
# Ya está generado; no hace falta correrlo:
python forensics/generate_signatures.py

# Una vez que recuperaste la clave privada d:
python forensics/verify_backdoor.py --key <d_en_hex>
```

## Estructura del repo

```
modelhub/
├── README.md                 
├── requirements.txt
├── config.yaml               
├── protocol.py               
├── handshake.py              
├── server.py                 
├── device.py                 
├── ca.py                     
├── telemetry.py              
├── bench.py                  
├── inventory/
│   └── inventario.csv        # plantilla para llenar (paso 1)
├── risk/
│   └── datasets.md           # los tres datos y su vida útil
├── forensics/                # material del ataque (extra)
│   ├── generate_signatures.py
│   ├── signatures.json
│   └── verify_backdoor.py
└── tests/
    ├── test_protocol.py
    ├── test_handshake.py
    ├── test_signing.py
    ├── test_session.py
    ├── test_telemetry.py
    └── test_ca.py
```