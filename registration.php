<?php
session_start();
if (isset($_SESSION["user"])) {
   header("Location: index.php");
}

function checkPasswordStrength($password) {
    // Define password strength requirements using regular expressions
    $uppercase = preg_match_all('@[A-Z]@', $password) >= 2;
    $lowercase = preg_match('@[a-z]@', $password);
    $number = preg_match('@[0-9]@', $password);
    $specialChar = preg_match_all('@[^\w]@', $password) >= 2;

    // Define minimum length for the password
    $minLength = 8;

    // Check if the password meets all the requirements
    return $uppercase && $lowercase && $number && $specialChar && strlen($password) >= $minLength;
}

function checkPhoneStrength($phone) {
    // Define password strength requirements using regular expressions

    
    $phone = preg_match('/^[789]\d{9}$/', $phone);



    // Define minimum length for the password
    $minLength = 10;

    // Check if the password meets all the requirements
    return $phone >= $minLength;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Registration Form</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/css/bootstrap.min.css" integrity="sha384-Zenh87qX5JnK2Jl0vWa8Ck2rdkQ2Bzep5IDxbcnCeuOxjzrPF/et3URy9Bv1WTRi" crossorigin="anonymous">
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <?php
        if (isset($_POST["submit"])) {
           $fullName = $_POST["fullname"];
           $email = $_POST["email"];
           $phone = $_POST["phone"];
           $password = $_POST["password"];
           $passwordRepeat = $_POST["repeat_password"];
           $address = $_POST["address"];

           $passwordHash = password_hash($password, PASSWORD_DEFAULT);

           $errors = array();

           if (empty($fullName) || empty($email) || empty($password) || empty($phone) || empty($passwordRepeat) || empty($address)) {
            array_push($errors, "All fields are required");
           }
           if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            array_push($errors, "Email is not valid");
           }
           if (strlen($password) < 8) {
            array_push($errors, "Password must be at least 8 characters long");
           }
           if ($password !== $passwordRepeat) {
            array_push($errors, "Password does not match");
           }
           if (!checkPasswordStrength($password)) {
            array_push($errors, "Password does not meet the strength requirements");
           }
           if (!checkPhoneStrength($phone)) {
            array_push($errors, "Phone does not meet the strength requirements");
           }
           
           require_once "database.php"; // Assuming you have a file named database.php for database connection


           $sql = "SELECT * FROM user WHERE email = ?";
           $stmt = mysqli_stmt_init($conn);

           if (mysqli_stmt_prepare($stmt, $sql)) {
                mysqli_stmt_bind_param($stmt, "s", $email);
                mysqli_stmt_execute($stmt);
                $result = mysqli_stmt_get_result($stmt);
                $rowCount = mysqli_num_rows($result);

                if ($rowCount > 0) {
                    array_push($errors, "Email already exists!");
                }
           }

           if (count($errors) > 0) {
                foreach ($errors as $error) {
                    echo "<div class='alert alert-danger'>$error</div>";
                }
           } else {

                $sql = "INSERT INTO user (full_name, email, phone, password, address) VALUES (?, ?, ?, ?, ?)";
                $stmt = mysqli_stmt_init($conn);

                if (mysqli_stmt_prepare($stmt, $sql)) {
                    mysqli_stmt_bind_param($stmt, "sssss", $fullName, $email, $phone, $passwordHash, $address);
                    mysqli_stmt_execute($stmt);
                    echo "<div class='alert alert-success'>You are registered successfully.</div>";
                } else {
                    die("Something went wrong");
                }
           }
        }
        ?>

        <form action="registration.php" method="post">
            <div class="form-group">
                <input type="text" class="form-control" name="fullname" placeholder="Full Name:">
            </div>
            <div class="form-group">
                <input type="email" class="form-control" name="email" placeholder="Email:">
            </div>
            <div class="form-group">
                <input type="tel" class="form-control" name="phone" placeholder="Phone:">
            </div>
            <div class="form-group">
                <input type="password" class="form-control" name="password" placeholder="Password:">
            </div>
            <div class="form-group">
                <input type="password" class="form-control" name="repeat_password" placeholder="Repeat Password:">
            </div>
            <div class="form-group">
                <input type="text" class="form-control" name="address" placeholder="Address:">
            </div>
            <div class="form-btn">
                <input type="submit" class="btn btn-primary" value="Register" name="submit">
            </div>
        </form>
        <div>
            <p>Already Registered <a href="login.php">Login Here</a></p>
        </div>
    </div>
</body>
</html>
