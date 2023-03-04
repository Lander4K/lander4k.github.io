---
title: Inyecciones NoSQL
published: true
img_path: /assets/Otros/NoSQL
categories: [HackTheBox, Vulnhub, NoSQL]
tags: [Hacking]
---

<img src="nosqli.png">

# Introducción

Las inyecciones NoSQL son una técnica de hacking ético que se utiliza para explotar vulnerabilidades en bases de datos NoSQL, las cuales se utilizan comúnmente en aplicaciones web modernas. En este post, explicaremos en qué consisten las inyecciones NoSQL, cómo funcionan y qué medidas se pueden tomar para prevenirlas.

# ¿Qué son las bases de datos NoSQL?
Las bases de datos NoSQL son sistemas de gestión de bases de datos que utilizan modelos de datos no relacionales. Estas bases de datos se utilizan comúnmente en aplicaciones web modernas, ya que ofrecen una mayor escalabilidad y flexibilidad que las bases de datos relacionales tradicionales.

Las bases de datos NoSQL se dividen en varias categorías, como bases de datos de documentos, bases de datos de grafos, bases de datos clave-valor, etc. Cada tipo de base de datos tiene sus propias características y funcionalidades.

# ¿Qué son las inyecciones NoSQL?
Las inyecciones NoSQL son una técnica de hacking ético que se utiliza para explotar vulnerabilidades en las bases de datos NoSQL. Estas vulnerabilidades se producen cuando una aplicación web utiliza entrada de usuario no validada en consultas de bases de datos NoSQL.

En una inyección NoSQL, el atacante utiliza una entrada malintencionada para modificar la consulta de la base de datos, lo que le permite obtener información confidencial o realizar acciones no autorizadas en la aplicación web.

# Cómo funcionan las inyecciones NoSQL
Las inyecciones NoSQL funcionan de manera similar a las inyecciones SQL, que se utilizan para explotar vulnerabilidades en bases de datos relacionales. En ambos casos, el atacante utiliza una entrada malintencionada para modificar la consulta de la base de datos y obtener información confidencial o realizar acciones no autorizadas en la aplicación web.

Sin embargo, hay algunas diferencias importantes entre las inyecciones NoSQL y las inyecciones SQL. En las bases de datos NoSQL, las consultas se realizan utilizando objetos JSON (JavaScript Object Notation) en lugar de lenguaje SQL. Además, las bases de datos NoSQL suelen utilizar diferentes tipos de operadores de consulta en lugar de los operadores tradicionales de SQL.

# Ejemplos de inyecciones NoSQL
A continuación, se presentan algunos ejemplos de inyecciones NoSQL:

## Ejemplo 1: Inyección de operador de igualdad

Supongamos que tenemos una aplicación web que utiliza una base de datos NoSQL para almacenar información de usuarios. La consulta de la base de datos para obtener la información de un usuario se ve así:

```js
db.users.find({ username: 'usuario1' })
```

En este caso, la consulta busca un usuario con el nombre de usuario 'usuario1'. Sin embargo, si el atacante proporciona una entrada malintencionada en el campo de nombre de usuario, como por ejemplo:

```python
' || '1'=='1
```

La consulta se modificará de la siguiente manera:

```js
db.users.find({ username: '' || '1'=='1' })
```

En este caso, la consulta siempre será verdadera, ya que '1'=='1' siempre es verdadero. Como resultado, la consulta devuelve la información de todos los usuarios de la base de datos, lo que permite al atacante obtener información confidencial de la aplicación.

## Ejemplo 2: Inyección de operador de comparación

Supongamos que tenemos una aplicación web que utiliza una base de datos NoSQL para almacenar información de productos. La consulta de la base de datos para obtener los productos con un precio menor que $50 se ve así:

```js
db.products.find({ price: { $lt: 50 } })
```

En este caso, la consulta busca los productos con un precio menor que $50. Sin embargo, si el atacante proporciona una entrada malintencionada en el campo de precio, como por ejemplo:

```bash
{ $gt: '' }
```

La consulta se modificará de la siguiente manera:

```js
db.products.find({ price: { $gt: '' } })
```

En este caso, la consulta siempre será verdadera, ya que $gt: '' es una comparación no válida. Como resultado, la consulta devuelve todos los productos de la base de datos, lo que permite al atacante obtener información confidencial de la aplicación.

## Ejemplo 3: Inyección de filtro

Supongamos que tenemos una aplicación web que utiliza una base de datos NoSQL para almacenar información de usuarios. La consulta de la base de datos para autenticar a un usuario se ve así:

```js
db.users.find({ username: '<username>', password: '<password>' })
```

En este caso, la consulta busca un usuario con el nombre de usuario y contraseña proporcionados. Sin embargo, si el atacante proporciona una entrada malintencionada en el campo de nombre de usuario, como por ejemplo:

```python
' || 1==1 || '
```

La consulta se modificará de la siguiente manera:

```js
db.users.find({ username: '' || 1==1 || '', password: '<password>' })
```

En este caso, la consulta siempre será verdadera, ya que la expresión ' || 1==1 || ' es una operación de comparación que siempre devuelve verdadero. Como resultado, la consulta devuelve todos los usuarios de la base de datos, lo que permite al atacante obtener información confidencial de la aplicación.

## Ejemplo 4: Inyección de agregación

Supongamos que tenemos una aplicación web que utiliza una base de datos NoSQL para almacenar información de productos. La consulta de la base de datos para obtener la cantidad total de ventas de un producto se ve así:

```js
db.sales.aggregate([
    { $match: { product_id: <product_id> } },
    { $group: { _id: null, total_sales: { $sum: '$quantity' } } }
])
```

En este caso, la consulta busca todas las ventas de un producto en particular y calcula la cantidad total de ventas. Sin embargo, si el atacante proporciona una entrada malintencionada en el campo de identificación del producto, como por ejemplo:

```bash
{ $ne: '' }
```

La consulta se modificará de la siguiente manera:

```js
db.sales.aggregate([
    { $match: { product_id: { $ne: '' } } },
    { $group: { _id: null, total_sales: { $sum: '$quantity' } } }
])
```

En este caso, la consulta buscará todas las ventas de cualquier producto, excepto el producto con identificación vacía. Como resultado, la consulta devuelve la cantidad total de ventas de todos los productos de la base de datos, lo que permite al atacante obtener información confidencial de la aplicación.

## Ejemplo 5: Inyección de valores booleanos

Supongamos que tenemos una aplicación web que utiliza una base de datos NoSQL para almacenar información de usuarios y para comprobar si un usuario tiene permisos para realizar ciertas acciones. La consulta de la base de datos para comprobar si un usuario tiene permisos para realizar una acción determinada se ve así:

```js
db.permissions.find({ user_id: <user_id>, action: <action> })
```

En este caso, la consulta busca una entrada en la colección "permissions" que coincida con el identificador de usuario y la acción especificados. Sin embargo, si el atacante proporciona una entrada malintencionada en el campo de acción, como por ejemplo:

```bash
{ $ne: '' }
```

La consulta se modificará de la siguiente manera:

```js
db.permissions.find({ user_id: <user_id>, action: { $ne: '' } })
```

En este caso, la consulta buscará todas las entradas de la colección "permissions" que no tengan un campo de acción vacío. Como resultado, la consulta devolverá todos los permisos de usuario, lo que permite al atacante realizar cualquier acción que esté permitida por la aplicación.

## Ejemplo 6: Inyección de comandos 

Supongamos que tenemos una aplicación web que utiliza una base de datos NoSQL para almacenar información de usuarios y para permitir a los usuarios cambiar su contraseña. La consulta de la base de datos para cambiar la contraseña de un usuario se ve así:

```js
db.users.update({ username: '<username>' }, { $set: { password: '<new_password>' } })
```

En este caso, la consulta actualiza el campo de contraseña para el usuario especificado. Sin embargo, si el atacante proporciona una entrada malintencionada en el campo de nombre de usuario, como por ejemplo:

```less
' || db.users.remove({}) ||
```

La consulta se modificará de la siguiente manera:

```js
db.users.update({ username: '' || db.users.remove({}) || }, { $set: { password: '<new_password>' } })
```

En este caso, la consulta eliminará todas las entradas de la colección "users" y luego actualizará el campo de contraseña para un usuario que no existe. Como resultado, la base de datos se vaciará y la aplicación se volverá inutilizable.

# Cómo prevenir las inyecciones NoSQL

Para prevenir las inyecciones NoSQL, es importante validar todas las entradas de usuario que se utilizan en las consultas de la base de datos. Esto se puede hacer utilizando bibliotecas de validación de entrada de usuario o implementando una capa de validación de entrada de usuario en la aplicación.

También es importante limitar los privilegios de la cuenta de base de datos utilizada por la aplicación. La cuenta de base de datos solo debe tener los permisos necesarios para realizar las operaciones requeridas por la aplicación y no debe tener permisos adicionales que puedan ser utilizados por un atacante para realizar acciones no autorizadas.

Además, se recomienda utilizar versiones actualizadas de las bibliotecas y frameworks utilizados en la aplicación web, ya que las versiones más recientes suelen incluir mejoras de seguridad y correcciones de vulnerabilidades conocidas.

# Conclusión 

Las inyecciones NoSQL son una técnica de hacking ético que se utiliza para explotar vulnerabilidades en las bases de datos NoSQL. Estas vulnerabilidades se producen cuando una aplicación web utiliza entrada de usuario no validada en consultas de bases de datos NoSQL. Para prevenir las inyecciones NoSQL, es importante validar todas las entradas de usuario que se utilizan en las consultas de la base de datos y limitar los privilegios de la cuenta de base de datos utilizada por la aplicación