<?php
$servername = "localhost";
$username = "root";
$password = "";
$database_name = "secronix";

// Create connection
$conn = new mysqli($servername, $username, $password,$database_name);

// Check connection
if ($conn->connect_error) {
    die("Database Connection failed: " . $conn->connect_error);
} 

?>