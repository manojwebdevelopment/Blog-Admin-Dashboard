<?php
// logout.php

session_start();
require_once 'includes/auth.php';

// Destroy session and redirect to login
logoutUser();
?>