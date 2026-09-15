# Datos que maneja ModelHub — vida útil declarada

_Nota interna del equipo de plataforma. La pongo por escrito porque cada vez que
hablamos de "cuánto tiene que durar seguro esto" terminamos con tres números
distintos en la cabeza. Estos son los acordados con Legal y con Producto._

Tenemos tres tipos de dato en producción. La vida útil no es cuánto los guardamos:
es cuánto tiempo **siguen siendo sensibles si alguien los intercepta hoy**. Eso es lo
que importa para decidir qué migrar primero (acordate del "harvest now, decrypt later":
lo que capturan hoy cifrado, lo descifran cuando tengan la máquina).

## 1. Telemetría operativa — 2 años

Estado de las cámaras: batería, temperatura, uptime, versión de firmware, contadores
de inferencia. Va cifrada en el canal y se guarda cifrada en reposo.

Sensible pero perecedero. A los dos años, la telemetría de una cámara es ruido
histórico: no le sirve a nadie. Si alguien la descifra en 2032, no pasa gran cosa.

## 2. Imágenes de pacientes del piloto clínico — 25 años

El piloto con el hospital manda recortes de imágenes para reentrenar el detector.
Son datos de salud de personas identificables. Legal es tajante: la obligación de
confidencialidad es de **25 años** desde la captura.

Este es el dato que más nos preocupa. Si alguien captura hoy el tráfico cifrado y lo
guarda, tiene 25 años de ventana para descifrarlo. Una cámara desplegada en 2026
sigue en el piso clínico varios años, y el dato que movió el primer día tiene que
seguir protegido hasta 2051.

## 3. Pesos del modelo propietario — 10 años

Los pesos que distribuimos firmados. Es la propiedad intelectual del producto: la
arquitectura y el entrenamiento nos costaron dos años y son la ventaja competitiva.

La firma no es confidencialidad, es integridad y autenticidad: que nadie distribuya
un modelo trucho como si fuera nuestro. Pero ojo con el marco temporal: un modelo que
firmamos hoy se sigue ejecutando en cámaras en el campo por ~10 años. Si en ese plazo
alguien puede falsificar nuestra firma, puede empujar un modelo con backdoor a toda la
flota. La ventana de riesgo de la firma es la vida del modelo en producción, no el
momento en que lo firmamos.
