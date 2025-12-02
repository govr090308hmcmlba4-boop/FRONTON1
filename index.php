<?php
session_start();
include "conexion.php"; // Tu archivo de conexión

$mensaje = "";
$modo = "login"; // Por defecto estamos en login

if ($_SERVER["REQUEST_METHOD"] == "POST") {

    if (isset($_POST['accion'])) {
        $accion = $_POST['accion'];

        if ($accion == "login") {

            // Verificar si existen las claves antes de usarlas
            $usuario = isset($_POST["usuario"]) ? trim($_POST["usuario"]) : "";
            $contrasena = isset($_POST["contrasena"]) ? trim($_POST["contrasena"]) : "";

            if ($usuario !== "" && $contrasena !== "") {
                $stmt = $conn->prepare("SELECT * FROM login WHERE usuario = ?");
                if (!$stmt) {
                    die("Error en preparación: " . $conn->error);
                }
                $stmt->bind_param("s", $usuario);
                $stmt->execute();
                $resultado = $stmt->get_result();

                if ($resultado->num_rows == 1) {
                    $fila = $resultado->fetch_assoc();
                    if (password_verify($contrasena, $fila['contrasena'])) {

                        // Guardamos sesión
                        $_SESSION['usuario'] = $usuario;
                        $_SESSION['rol'] = $fila['rol'];

                        // REDIRECCIÓN SEGÚN ROL
                        if ($fila['rol'] === 'administrador') {
                            header("Location: admin.html");
                        } else {
                            header("Location: inicio.html");
                        }
                        exit();

                    } else {
                        $mensaje = "Contraseña incorrecta";
                    }
                } else {
                    $mensaje = "Usuario no encontrado";
                }
            } else {
                $mensaje = "Complete todos los campos";
            }

        } elseif ($accion == "agregar") {
            $modo = "agregar";

        } elseif ($accion == "guardar") {

            $usuario = isset($_POST['usuario']) ? trim($_POST['usuario']) : "";
            $contrasena = isset($_POST['contrasena']) ? trim($_POST['contrasena']) : "";
            $rol = isset($_POST['rol']) ? $_POST['rol'] : 'usuario';

            if ($usuario !== "" && $contrasena !== "") {

                $stmt = $conn->prepare("SELECT * FROM login WHERE usuario = ?");
                if (!$stmt) {
                    die("Error en preparación: " . $conn->error);
                }
                $stmt->bind_param("s", $usuario);
                $stmt->execute();
                $resultado = $stmt->get_result();

                if ($resultado->num_rows > 0) {
                    $mensaje = "El usuario ya existe";
                    $modo = "agregar";
                } else {
                    $roles_validos = ['usuario','administrador'];
                    if (!in_array($rol, $roles_validos)) {
                        $rol = 'usuario';
                    }

                    $pass_hash = password_hash($contrasena, PASSWORD_DEFAULT);
                    $stmt = $conn->prepare("INSERT INTO login (usuario, contrasena, rol) VALUES (?, ?, ?)");
                    if (!$stmt) {
                        die("Error en preparación: " . $conn->error);
                    }
                    $stmt->bind_param("sss", $usuario, $pass_hash, $rol);
                    if ($stmt->execute()) {
                        $mensaje = "Usuario agregado correctamente";
                        $modo = "login";
                    } else {
                        $mensaje = "Error al agregar usuario";
                        $modo = "agregar";
                    }
                }
            } else {
                $mensaje = "Complete todos los campos";
                $modo = "agregar";
            }
        }
    }
}
?>

<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>Inicio de Sesión - Frontón</title>
<style>
body {
    font-family: Arial, sans-serif;
    background-color: #e0f7fa;
    display: flex;
    justify-content: center;
    align-items: center;
    height: 100vh;
    margin: 0;
}
.container {
    background-color: #b2dfdb;
    padding: 30px;
    border-radius: 12px;
    box-shadow: 0 4px 15px rgba(0,0,0,0.3);
    text-align: center;
    width: 350px;
}
.container h2 { margin-bottom: 20px; color: #004d40; }
input, select {
    width: 90%;
    padding: 10px;
    margin: 8px 0;
    border-radius: 6px;
    border: 1px solid #004d40;
    font-size: 1em;
}
.btn {
    width: 95%;
    padding: 12px;
    background-color: #00796b;
    color: white;
    border: none;
    border-radius: 6px;
    cursor: pointer;
    margin-top: 10px;
    font-size: 1em;
    transition: 0.3s;
}
.btn:hover { background-color: #004d40; }
.btn-agregar { background-color: #26a69a; }
.btn-agregar:hover { background-color: #00796b; }
#mensaje { margin-top:12px; font-weight:bold; color:red; }
</style>
</head>
<body>

<div class="container">
    <?php if ($modo == "login") { ?>
        <h2>Iniciar Sesión</h2>
        <form method="POST" action="">
            <input type="text" name="usuario" placeholder="Usuario" required><br>
            <input type="password" name="contrasena" placeholder="Contraseña" required><br>
            <input type="hidden" name="accion" value="login">
            <button type="submit" class="btn">Entrar</button>
        </form>
        <form method="POST" action="">
            <input type="hidden" name="accion" value="agregar">
            <button type="submit" class="btn btn-agregar">Agregar Nuevo Usuario</button>
        </form>
    <?php } elseif ($modo == "agregar") { ?>
        <h2>Agregar Usuario</h2>
        <form method="POST" action="">
            <input type="text" name="usuario" placeholder="Usuario" required><br>
            <input type="password" name="contrasena" placeholder="Contraseña" required><br>
            <select name="rol" required>
                <option value="usuario">Usuario</option>
                <option value="administrador">Administrador</option>
            </select><br>
            <input type="hidden" name="accion" value="guardar">
            <button type="submit" class="btn btn-agregar">Guardar Usuario</button>
        </form>
        <form method="POST" action="">
            <input type="hidden" name="accion" value="login">
            <button type="submit" class="btn" style="background-color:#00796b; margin-top:10px;">Regresar</button>
        </form>
    <?php } ?>
    <p id="mensaje"><?php echo $mensaje; ?></p>
</div>

</body>
</html>
