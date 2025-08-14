<?php
// examples/permission_examples.php
// This file shows how to use the permission system

session_start();
require_once '../includes/auth.php';

// Example 1: Check if user is logged in
if (!isLoggedIn()) {
    header("Location: login.php");
    exit();
}

// Example 2: Require login (redirect if not logged in)
requireLogin();

// Example 3: Check specific role
if (hasRole('admin')) {
    echo "User is an admin";
}

// Example 4: Check specific permission
if (hasPermission('create_post')) {
    echo "User can create posts";
}

// Example 5: Require specific permission (redirect if not allowed)
requirePermission('manage_users');

// Example 6: Check if user can edit a specific post
$post_id = 123;
if (canEditPost($post_id)) {
    echo "User can edit this post";
}

// Example 7: Get current user information
$current_user = getCurrentUser();
if ($current_user) {
    echo "Current user: " . $current_user['username'];
    echo "Role: " . $current_user['role'];
}

// Example 8: Different content based on role
switch ($_SESSION['role']) {
    case 'admin':
        echo "Admin dashboard content";
        break;
    case 'author':
        echo "Author dashboard content";
        break;
    case 'viewer':
        echo "Viewer dashboard content";
        break;
}

// Example 9: Conditional navigation based on permissions
?>

<!DOCTYPE html>
<html>
<head>
    <title>Permission Examples</title>
</head>
<body>
    <nav>
        <ul>
            <li><a href="dashboard.php">Dashboard</a></li>
            
            <?php if (hasPermission('create_post')): ?>
            <li><a href="posts.php">Posts</a></li>
            <?php endif; ?>
            
            <?php if (hasPermission('manage_categories')): ?>
            <li><a href="categories.php">Categories</a></li>
            <?php endif; ?>
            
            <?php if (hasPermission('manage_comments')): ?>
            <li><a href="comments.php">Comments</a></li>
            <?php endif; ?>
            
            <?php if (hasPermission('manage_users')): ?>
            <li><a href="users.php">Users</a></li>
            <li><a href="register.php">Add User</a></li>
            <?php endif; ?>
            
            <?php if (hasPermission('manage_settings')): ?>
            <li><a href="settings.php">Settings</a></li>
            <?php endif; ?>
        </ul>
    </nav>

    <main>
        <h1>Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?>!</h1>
        <p>Your role: <?php echo ucfirst($_SESSION['role']); ?></p>
        
        <h2>Your Permissions:</h2>
        <ul>
            <?php if (hasPermission('create_post')): ?>
            <li>✅ Create Posts</li>
            <?php else: ?>
            <li>❌ Create Posts</li>
            <?php endif; ?>
            
            <?php if (hasPermission('edit_own_post')): ?>
            <li>✅ Edit Own Posts</li>
            <?php else: ?>
            <li>❌ Edit Own Posts</li>
            <?php endif; ?>
            
            <?php if (hasPermission('edit_any_post')): ?>
            <li>✅ Edit Any Post</li>
            <?php else: ?>
            <li>❌ Edit Any Post</li>
            <?php endif; ?>
            
            <?php if (hasPermission('delete_post')): ?>
            <li>✅ Delete Posts</li>
            <?php else: ?>
            <li>❌ Delete Posts</li>
            <?php endif; ?>
            
            <?php if (hasPermission('manage_users')): ?>
            <li>✅ Manage Users</li>
            <?php else: ?>
            <li>❌ Manage Users</li>
            <?php endif; ?>
            
            <?php if (hasPermission('manage_categories')): ?>
            <li>✅ Manage Categories</li>
            <?php else: ?>
            <li>❌ Manage Categories</li>
            <?php endif; ?>
            
            <?php if (hasPermission('manage_comments')): ?>
            <li>✅ Manage Comments</li>
            <?php else: ?>
            <li>❌ Manage Comments</li>
            <?php endif; ?>
            
            <?php if (hasPermission('manage_settings')): ?>
            <li>✅ Manage Settings</li>
            <?php else: ?>
            <li>❌ Manage Settings</li>
            <?php endif; ?>
        </ul>

        <h2>Action Examples:</h2>
        
        <?php if (hasPermission('create_post')): ?>
        <div class="action-section">
            <h3>Create New Post</h3>
            <form action="create_post.php" method="POST">
                <input type="text" name="title" placeholder="Post Title" required>
                <textarea name="content" placeholder="Post Content" required></textarea>
                <button type="submit">Create Post</button>
            </form>
        </div>
        <?php endif; ?>
        
        <?php if (hasPermission('manage_users')): ?>
        <div class="action-section">
            <h3>User Management</h3>
            <a href="register.php">Add New User</a>
            <a href="users.php">Manage Users</a>
        </div>
        <?php endif; ?>
        
        <?php if (hasPermission('manage_settings')): ?>
        <div class="action-section">
            <h3>Site Settings</h3>
            <a href="settings.php">Edit Site Settings</a>
        </div>
        <?php endif; ?>
    </main>
</body>
</html>

<?php
// Example 10: Database operations with permission checks

// Function to create a post (only if user has permission)
function createPost($title, $content, $category_id = null) {
    if (!hasPermission('create_post')) {
        return ['success' => false, 'message' => 'Permission denied'];
    }
    
    $connection = getConnection();
    
    try {
        $author_id = $_SESSION['user_id'];
        $slug = generateSlug($title);
        
        $query = "INSERT INTO posts (title, slug, content, category_id, author_id, status) VALUES (?, ?, ?, ?, ?, 'draft')";
        $stmt = executePreparedStatement($connection, $query, "sssii", [$title, $slug, $content, $category_id, $author_id]);
        
        $post_id = $connection->insert_id;
        $stmt->close();
        closeConnection($connection);
        
        return ['success' => true, 'message' => 'Post created successfully', 'post_id' => $post_id];
        
    } catch (Exception $e) {
        closeConnection($connection);
        return ['success' => false, 'message' => 'Failed to create post: ' . $e->getMessage()];
    }
}

// Function to delete a post (only if user has permission)
function deletePost($post_id) {
    if (!hasPermission('delete_post') && !canEditPost($post_id)) {
        return ['success' => false, 'message' => 'Permission denied'];
    }
    
    $connection = getConnection();
    
    try {
        $query = "DELETE FROM posts WHERE id = ?";
        $stmt = executePreparedStatement($connection, $query, "i", [$post_id]);
        
        $stmt->close();
        closeConnection($connection);
        
        return ['success' => true, 'message' => 'Post deleted successfully'];
        
    } catch (Exception $e) {
        closeConnection($connection);
        return ['success' => false, 'message' => 'Failed to delete post: ' . $e->getMessage()];
    }
}

// Function to update user role (admin only)
function updateUserRole($user_id, $new_role) {
    if (!hasPermission('manage_users')) {
        return ['success' => false, 'message' => 'Permission denied'];
    }
    
    $connection = getConnection();
    
    try {
        $query = "UPDATE users SET role = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?";
        $stmt = executePreparedStatement($connection, $query, "si", [$new_role, $user_id]);
        
        $stmt->close();
        closeConnection($connection);
        
        return ['success' => true, 'message' => 'User role updated successfully'];
        
    } catch (Exception $e) {
        closeConnection($connection);
        return ['success' => false, 'message' => 'Failed to update role: ' . $e->getMessage()];
    }
}

// Helper function to generate slug from title
function generateSlug($title) {
    $slug = strtolower(trim(preg_replace('/[^A-Za-z0-9-]+/', '-', $title)));
    return $slug;
}
?>