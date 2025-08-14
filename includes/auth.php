<?php 

require_once 'config/database.php';


function sanitize($data) {
    $connection = getConnection();
    return mysqli_real_escape_string($connection, htmlspecialchars(trim($data)));
}


//register user functions

function registerUser($username, $email, $password, $role='viewer') {
    $connection = getConnection();

    try{

        $check_query = 'SELECT id FROM users WHERE username = ? OR email = ? ';
        $check_stmt = executePreparedStatement($connection, $check_query, 'ss', [$username, $email]);
        $check_result = getPreparedResult($check_stmt);

        if($check_result->num_rows > 0) {
            $check_result->close();
            closeConnection($connection);
            return ['success' => false, 'message' => 'User already exists']; 
        }

        $check_stmt->close();

        //Hash password
        $hashed_password = password_hash($password, PASSWORD_BCRYPT);

        //Insert new user
        $insert_query = 'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)';
        $insert_stmt = executePreparedStatement($connection, $insert_query, 'ssss', [$username, $email, $hashed_password, $role]);

        if($insert_stmt->affected_rows > 0) {
            $user_id = $connection->insert_id;
            $insert_stmt->close();
            closeConnection($connection);
            return ['success' => true, 'message' => 'User registered successfully', 'user_id' => $user_id];
        } else {
            $insert_stmt->close();
            closeConnection($connection);
            return ['success' => false, 'message' => 'User registration failed'];
        }
    }
    catch(Exception $e) {
        closeConnection($connection);
       return ['success' => false, 'message' => 'Database connection failed: '. $e->getMessage()];
    }
}




// Helper function to get and clear session messages
function getSessionMessages() {
    $messages = [];
    $types = ['error', 'success', 'warning', 'info', 'published'];
    
    foreach ($types as $type) {
        if (isset($_SESSION[$type]) && !empty($_SESSION[$type])) {
            $messages[$type] = $_SESSION[$type];
            unset($_SESSION[$type]); // Clear after getting
        }
    }
    
    return $messages;
}

// Login user function
function loginUser($username, $password) {
    $connection = getConnection();
    
    try {
        $query = "SELECT id, username, email, password, role, status FROM users WHERE (username = ? OR email = ?) AND status = 'active'";
        $stmt = executePreparedStatement($connection, $query, "ss", [$username, $username]);
        $result = getPreparedResult($stmt);
        
        if ($result->num_rows == 1) {
            $user = $result->fetch_assoc();
            
            if (password_verify($password, $user['password'])) {
                // Set session variables
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['email'] = $user['email'];
                $_SESSION['role'] = $user['role'];
                $_SESSION['logged_in'] = true;
                
                $stmt->close();
                closeConnection($connection);
                return ['success' => true, 'message' => 'Login successful'];
            }
        }
        
        $stmt->close();
        closeConnection($connection);
        return ['success' => false, 'message' => 'Invalid username/email or password'];
        
    } catch (Exception $e) {
        closeConnection($connection);
        return ['success' => false, 'message' => 'Login failed: ' . $e->getMessage()];
    }
}

// Logout function
function logoutUser() {
    session_destroy();
    header("Location: login.php");
    exit();
}

// Check if user is logged in
function isLoggedIn() {
    return isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true;
}

// Check user role
function hasRole($role) {
    if (!isLoggedIn()) {
        return false;
    }
    return $_SESSION['role'] === $role;
}

// Check if user has permission for action
function hasPermission($action) {
    if (!isLoggedIn()) {
        return false;
    }
    
    $role = $_SESSION['role'];
    
    $permissions = [
        'admin' => [
            'create_post', 'edit_post', 'delete_post', 'publish_post',
            'manage_users', 'manage_categories', 'manage_comments',
            'view_dashboard', 'manage_settings', 'edit_any_post'
        ],
        'author' => [
            'create_post', 'edit_own_post', 'view_dashboard'
        ],
        'viewer' => [
            'view_dashboard'
        ]
    ];
    
    return in_array($action, $permissions[$role]);
}

// Check if user can edit specific post
function canEditPost($post_id) {
    if (!isLoggedIn()) {
        return false;
    }
    
    if ($_SESSION['role'] === 'admin') {
        return true;
    }
    
    if ($_SESSION['role'] === 'author') {
        $connection = getConnection();
        $query = "SELECT author_id FROM posts WHERE id = ?";
        $stmt = executePreparedStatement($connection, $query, "i", [$post_id]);
        $result = getPreparedResult($stmt);
        
        if ($result->num_rows == 1) {
            $post = $result->fetch_assoc();
            $can_edit = $post['author_id'] == $_SESSION['user_id'];
            $stmt->close();
            closeConnection($connection);
            return $can_edit;
        }
        
        $stmt->close();
        closeConnection($connection);
    }
    
    return false;
}

// Redirect if not logged in
function requireLogin() {
    if (!isLoggedIn()) {
        header("Location: login.php");
        exit();
    }
}

// Redirect if no permission
function requirePermission($action) {
    if (!hasPermission($action)) {
        header("Location: dashboard.php?error=access_denied");
        exit();
    }
}

// Get current user info
function getCurrentUser() {
    if (isLoggedIn()) {
        return [
            'id' => $_SESSION['user_id'],
            'username' => $_SESSION['username'],
            'email' => $_SESSION['email'],
            'role' => $_SESSION['role']
        ];
    }
    return null;
}

// Get user by ID
function getUserById($user_id) {
    $connection = getConnection();
    
    try {
        $query = "SELECT id, username, email, role, status, created_at FROM users WHERE id = ?";
        $stmt = executePreparedStatement($connection, $query, "i", [$user_id]);
        $result = getPreparedResult($stmt);
        
        $user = null;
        if ($result->num_rows == 1) {
            $user = $result->fetch_assoc();
        }
        
        $stmt->close();
        closeConnection($connection);
        return $user;
        
    } catch (Exception $e) {
        closeConnection($connection);
        return null;
    }
}

// Update user
function updateUser($user_id, $username, $email, $role, $status = 'active') {
    $connection = getConnection();
    
    try {
        // Check if username or email exists for other users
        $check_query = "SELECT id FROM users WHERE (username = ? OR email = ?) AND id != ?";
        $check_stmt = executePreparedStatement($connection, $check_query, "ssi", [$username, $email, $user_id]);
        $check_result = getPreparedResult($check_stmt);
        
        if ($check_result->num_rows > 0) {
            $check_stmt->close();
            closeConnection($connection);
            return ['success' => false, 'message' => 'Username or email already exists'];
        }
        
        $check_stmt->close();
        
        $query = "UPDATE users SET username = ?, email = ?, role = ?, status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?";
        $stmt = executePreparedStatement($connection, $query, "ssssi", [$username, $email, $role, $status, $user_id]);
        
        $stmt->close();
        closeConnection($connection);
        
        return ['success' => true, 'message' => 'User updated successfully'];
        
    } catch (Exception $e) {
        closeConnection($connection);
        return ['success' => false, 'message' => 'Update failed: ' . $e->getMessage()];
    }
}

// Delete user
function deleteUser($user_id) {
    $connection = getConnection();
    
    try {
        // Check if this is the last admin
        $admin_count_query = "SELECT COUNT(*) as count FROM users WHERE role = 'admin' AND status = 'active'";
        $admin_stmt = executePreparedStatement($connection, $admin_count_query);
        $admin_result = getPreparedResult($admin_stmt);
        $admin_count = $admin_result->fetch_assoc()['count'];
        $admin_stmt->close();
        
        // Check user role
        $user_query = "SELECT role FROM users WHERE id = ?";
        $user_stmt = executePreparedStatement($connection, $user_query, "i", [$user_id]);
        $user_result = getPreparedResult($user_stmt);
        $user = $user_result->fetch_assoc();
        $user_stmt->close();
        
        if ($user['role'] === 'admin' && $admin_count <= 1) {
            closeConnection($connection);
            return ['success' => false, 'message' => 'Cannot delete the last admin user'];
        }
        
        $delete_query = "DELETE FROM users WHERE id = ?";
        $delete_stmt = executePreparedStatement($connection, $delete_query, "i", [$user_id]);
        
        $delete_stmt->close();
        closeConnection($connection);
        
        return ['success' => true, 'message' => 'User deleted successfully'];
        
    } catch (Exception $e) {
        closeConnection($connection);
        return ['success' => false, 'message' => 'Delete failed: ' . $e->getMessage()];
    }
}

// Get all users
function getAllUsers() {
    $connection = getConnection();
    
    try {
        $query = "SELECT id, username, email, role, status, created_at FROM users ORDER BY created_at DESC";
        $stmt = executePreparedStatement($connection, $query);
        $result = getPreparedResult($stmt);
        
        $users = [];
        while ($row = $result->fetch_assoc()) {
            $users[] = $row;
        }
        
        $stmt->close();
        closeConnection($connection);
        
        return $users;
        
    } catch (Exception $e) {
        closeConnection($connection);
        return [];
    }
}

// Validate input data
function validateUserInput($username, $email, $password = null, $role = 'viewer') {
    $errors = [];
    
    // Validate username
    if (empty($username)) {
        $errors[] = 'Username is required';
    } elseif (strlen($username) < 3) {
        $errors[] = 'Username must be at least 3 characters long';
    } elseif (strlen($username) > 50) {
        $errors[] = 'Username must not exceed 50 characters';
    } elseif (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
        $errors[] = 'Username can only contain letters, numbers, and underscores';
    }
    
    // Validate email
    if (empty($email)) {
        $errors[] = 'Email is required';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = 'Please enter a valid email address';
    } elseif (strlen($email) > 100) {
        $errors[] = 'Email must not exceed 100 characters';
    }
    
    // Validate password (only if provided)
    if ($password !== null) {
        if (empty($password)) {
            $errors[] = 'Password is required';
        } elseif (strlen($password) < 6) {
            $errors[] = 'Password must be at least 6 characters long';
        } elseif (strlen($password) > 255) {
            $errors[] = 'Password is too long';
        }
    }
    
    // Validate role
    $valid_roles = ['admin', 'author', 'viewer'];
    if (!in_array($role, $valid_roles)) {
        $errors[] = 'Invalid role selected';
    }
    
    return $errors;
}
?>