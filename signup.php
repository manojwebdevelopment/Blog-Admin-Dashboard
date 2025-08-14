<?php
session_start();
require_once 'includes/auth.php';

// Check if user is logged in and has permission to register users
// if (!isLoggedIn()) {
//     header("Location: login.php");
//     exit();
// }

// // Only admin can register users
// if (!hasPermission('manage_users')) {
//     header("Location: dashboard.php?error=access_denied");
//     exit();
// }

// Get session messages
$sessionMessages = getSessionMessages();
$username = '';
$email = '';
$role = 'viewer';

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = sanitize($_POST['username'] ?? '');
    $email = sanitize($_POST['email'] ?? '');
    $password = sanitize($_POST['password'] ?? '');
    $confirm_password = sanitize($_POST['confirm_password'] ?? '');
    $role = sanitize($_POST['role'] ?? 'viewer');

    // Validate input
    if (empty($username)) {
        $_SESSION['error'] = 'Username is required';
    } elseif (empty($email)) {
        $_SESSION['error'] = 'Email is required';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $_SESSION['error'] = 'Please enter a valid email address';
    } elseif (empty($password)) {
        $_SESSION['error'] = 'Password is required';
    } elseif (strlen($password) < 6) {
        $_SESSION['error'] = 'Password must be at least 6 characters long';
    } elseif ($password !== $confirm_password) {
        $_SESSION['error'] = 'Passwords do not match';
    } elseif (empty($role) || !in_array($role, ['admin', 'author', 'viewer'])) {
        $_SESSION['error'] = 'Please select a valid role';
    } else {
        // Register the user
        $result = registerUser($username, $email, $password, $role);

        if ($result['success']) {
            $_SESSION['success'] = $result['message'];
            // Clear form data on success
            $username = '';
            $email = '';
            $role = 'viewer';
            // Redirect to prevent resubmission
            header("Location: " . $_SERVER['PHP_SELF']);
            exit();
        } else {
            $_SESSION['error'] = $result['message'];
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register User - Blog Admin Panel</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/toastr.js/latest/toastr.min.css">
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
        }

        .register-container {
            max-width: 500px;
            margin: 0 auto;
        }

        .card {
            border: none;
            border-radius: 15px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
        }

        .card-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border: none;
            border-radius: 15px 15px 0 0;
            color: white;
            text-align: center;
            padding: 2rem 1.5rem 1.5rem;
        }

        .card-body {
            padding: 2rem;
        }

        .form-control,
        .form-select {
            border-radius: 10px;
            border: 2px solid #e9ecef;
            padding: 0.75rem 1rem;
        }

        .form-control:focus,
        .form-select:focus {
            border-color: #667eea;
            box-shadow: 0 0 0 0.25rem rgba(102, 126, 234, 0.25);
        }

        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border: none;
            border-radius: 10px;
            padding: 0.75rem 1.5rem;
            font-weight: 500;
        }

        .btn-primary:hover {
            background: linear-gradient(135deg, #5a6fd8 0%, #6a4190 100%);
        }

        .btn-secondary {
            border-radius: 10px;
            padding: 0.75rem 1.5rem;
        }

        .input-group-text {
            border-radius: 10px 0 0 10px;
            border: 2px solid #e9ecef;
            border-right: none;
            background-color: #f8f9fa;
        }

        .form-control.with-icon,
        .form-select.with-icon {
            border-left: none;
            border-radius: 0 10px 10px 0;
        }
    </style>
</head>

<body>
    <div class="container">
        <div class="register-container">
            <div class="card">
                <div class="card-header">
                    <h3 class="mb-2">
                        <i class="fas fa-user-plus me-2"></i>
                        Register New User
                    </h3>
                    <p class="mb-0">Create a new user account</p>
                </div>
                <div class="card-body">
                    <form method="POST" action="">
                        <div class="mb-3">
                            <div class="input-group">
                                <span class="input-group-text">
                                    <i class="fas fa-user"></i>
                                </span>
                                <input type="text" 
                                       class="form-control with-icon" 
                                       name="username" 
                                       placeholder="Username"
                                       value="<?php echo htmlspecialchars($username); ?>"
                                       >
                            </div>
                            <small class="text-muted">Username must be 3-50 characters (letters, numbers, underscore only)</small>
                        </div>

                        <div class="mb-3">
                            <div class="input-group">
                                <span class="input-group-text">
                                    <i class="fas fa-envelope"></i>
                                </span>
                                <input type="email" 
                                       class="form-control with-icon" 
                                       name="email" 
                                       placeholder="Email Address"
                                       value="<?php echo htmlspecialchars($email); ?>"
                                       >
                            </div>
                        </div>

                        <div class="mb-3">
                            <div class="input-group">
                                <span class="input-group-text">
                                    <i class="fas fa-shield-alt"></i>
                                </span>
                                <select class="form-select with-icon" name="role" >
                                    <option value="">Select Role</option>
                                    <option value="admin" <?php echo ($role === 'admin') ? 'selected' : ''; ?>>
                                        Admin - Full access to all features
                                    </option>
                                    <option value="author" <?php echo ($role === 'author') ? 'selected' : ''; ?>>
                                        Author - Can create and edit own posts
                                    </option>
                                    <option value="viewer" <?php echo ($role === 'viewer') ? 'selected' : ''; ?>>
                                        Viewer - Read-only dashboard access
                                    </option>
                                </select>
                            </div>
                        </div>

                        <div class="mb-3">
                            <div class="input-group">
                                <span class="input-group-text">
                                    <i class="fas fa-lock"></i>
                                </span>
                                <input type="password" 
                                       class="form-control with-icon" 
                                       name="password" 
                                       placeholder="Password"
                                       >
                            </div>
                            <small class="text-muted">Password must be at least 6 characters long</small>
                        </div>

                        <div class="mb-4">
                            <div class="input-group">
                                <span class="input-group-text">
                                    <i class="fas fa-lock"></i>
                                </span>
                                <input type="password" 
                                       class="form-control with-icon" 
                                       name="confirm_password" 
                                       placeholder="Confirm Password"
                                       >
                            </div>
                        </div>

                        <div class="d-grid gap-2">
                            <button type="submit" class="btn btn-primary">
                                <i class="fas fa-user-plus me-2"></i>
                                Register User
                            </button>
                            <a href="dashboard.php" class="btn btn-secondary">
                                <i class="fas fa-arrow-left me-2"></i>
                                Back to Dashboard
                            </a>
                        </div>
                    </form>

                    <hr class="my-4">

                    <div class="text-center">
                        <small class="text-muted">
                            <strong>Role Permissions:</strong><br>
                            <i class="fas fa-crown text-warning"></i> <strong>Admin:</strong> Full system access<br>
                            <i class="fas fa-pen text-info"></i> <strong>Author:</strong> Create & edit own posts<br>
                            <i class="fas fa-eye text-secondary"></i> <strong>Viewer:</strong> Dashboard access only
                        </small>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- jQuery -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
    <!-- Toastr JS -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/toastr.js/latest/toastr.min.js"></script>
    <!-- Bootstrap JS -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/js/bootstrap.bundle.min.js"></script>

    <script>
        // Toastr config
        toastr.options = {
            "closeButton": true,
            "progressBar": true,
            "positionClass": "toast-top-right",
            "timeOut": "5000"
        };

        // Show session messages
        <?php foreach ($sessionMessages as $type => $message): ?>
            <?php if ($type === 'published'): ?>
                toastr.success("<?php echo addslashes($message); ?>");
            <?php else: ?>
                toastr.<?php echo $type; ?>("<?php echo addslashes($message); ?>");
            <?php endif; ?>
        <?php endforeach; ?>
    </script>
</body>

</html>