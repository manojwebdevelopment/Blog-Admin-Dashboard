<?php
session_start();
require_once 'includes/auth.php';

// Check if user is logged in
requireLogin();

$current_user = getCurrentUser();

// Get dashboard statistics
function getDashboardStats($user_id, $role) {
    $connection = getConnection();
    $stats = [];
    
    try {
        // Total posts
        if ($role === 'admin') {
            $posts_query = "SELECT COUNT(*) as total FROM posts";
            $posts_stmt = executePreparedStatement($connection, $posts_query);
        } else {
            $posts_query = "SELECT COUNT(*) as total FROM posts WHERE author_id = ?";
            $posts_stmt = executePreparedStatement($connection, $posts_query, "i", [$user_id]);
        }
        $posts_result = getPreparedResult($posts_stmt);
        $stats['total_posts'] = $posts_result->fetch_assoc()['total'];
        $posts_stmt->close();
        
        // Published posts
        if ($role === 'admin') {
            $published_query = "SELECT COUNT(*) as total FROM posts WHERE status = 'published'";
            $published_stmt = executePreparedStatement($connection, $published_query);
        } else {
            $published_query = "SELECT COUNT(*) as total FROM posts WHERE status = 'published' AND author_id = ?";
            $published_stmt = executePreparedStatement($connection, $published_query, "i", [$user_id]);
        }
        $published_result = getPreparedResult($published_stmt);
        $stats['published_posts'] = $published_result->fetch_assoc()['total'];
        $published_stmt->close();
        
        // Draft posts
        if ($role === 'admin') {
            $draft_query = "SELECT COUNT(*) as total FROM posts WHERE status = 'draft'";
            $draft_stmt = executePreparedStatement($connection, $draft_query);
        } else {
            $draft_query = "SELECT COUNT(*) as total FROM posts WHERE status = 'draft' AND author_id = ?";
            $draft_stmt = executePreparedStatement($connection, $draft_query, "i", [$user_id]);
        }
        $draft_result = getPreparedResult($draft_stmt);
        $stats['draft_posts'] = $draft_result->fetch_assoc()['total'];
        $draft_stmt->close();
        
        // Comments (admin only)
        if ($role === 'admin') {
            $comments_query = "SELECT COUNT(*) as total FROM comments";
            $comments_stmt = executePreparedStatement($connection, $comments_query);
            $comments_result = getPreparedResult($comments_stmt);
            $stats['total_comments'] = $comments_result->fetch_assoc()['total'];
            $comments_stmt->close();
            
            // Pending comments
            $pending_query = "SELECT COUNT(*) as total FROM comments WHERE status = 'pending'";
            $pending_stmt = executePreparedStatement($connection, $pending_query);
            $pending_result = getPreparedResult($pending_stmt);
            $stats['pending_comments'] = $pending_result->fetch_assoc()['total'];
            $pending_stmt->close();
        }
        
        // Users (admin only)
        if ($role === 'admin') {
            $users_query = "SELECT COUNT(*) as total FROM users WHERE status = 'active'";
            $users_stmt = executePreparedStatement($connection, $users_query);
            $users_result = getPreparedResult($users_stmt);
            $stats['total_users'] = $users_result->fetch_assoc()['total'];
            $users_stmt->close();
            
            // Categories
            $categories_query = "SELECT COUNT(*) as total FROM categories";
            $categories_stmt = executePreparedStatement($connection, $categories_query);
            $categories_result = getPreparedResult($categories_stmt);
            $stats['total_categories'] = $categories_result->fetch_assoc()['total'];
            $categories_stmt->close();
        }
        
    } catch (Exception $e) {
        error_log("Dashboard stats error: " . $e->getMessage());
    }
    
    closeConnection($connection);
    return $stats;
}

// Get recent posts
function getRecentPosts($user_id, $role, $limit = 5) {
    $connection = getConnection();
    $posts = [];
    
    try {
        if ($role === 'admin') {
            $query = "SELECT p.id, p.title, p.status, p.created_at, u.username as author 
                     FROM posts p 
                     JOIN users u ON p.author_id = u.id 
                     ORDER BY p.created_at DESC 
                     LIMIT ?";
            $stmt = executePreparedStatement($connection, $query, "i", [$limit]);
        } else {
            $query = "SELECT p.id, p.title, p.status, p.created_at, u.username as author 
                     FROM posts p 
                     JOIN users u ON p.author_id = u.id 
                     WHERE p.author_id = ? 
                     ORDER BY p.created_at DESC 
                     LIMIT ?";
            $stmt = executePreparedStatement($connection, $query, "ii", [$user_id, $limit]);
        }
        
        $result = getPreparedResult($stmt);
        while ($row = $result->fetch_assoc()) {
            $posts[] = $row;
        }
        $stmt->close();
        
    } catch (Exception $e) {
        error_log("Recent posts error: " . $e->getMessage());
    }
    
    closeConnection($connection);
    return $posts;
}

$stats = getDashboardStats($current_user['id'], $current_user['role']);
$recent_posts = getRecentPosts($current_user['id'], $current_user['role']);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - Blog Admin Panel</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <!-- Sidebar -->
    <div class="sidebar">
        <div class="sidebar-header">
            <a href="dashboard.php" class="sidebar-brand">
                <i class="fas fa-blog me-2"></i>
                Blog Admin
            </a>
        </div>
        
        <nav class="sidebar-nav">
            <ul class="nav flex-column">
                <li class="nav-item">
                    <a class="nav-link active" href="dashboard.php">
                        <i class="fas fa-tachometer-alt"></i>
                        Dashboard
                    </a>
                </li>
                
                <?php if (hasPermission('create_post')): ?>
                <li class="nav-item">
                    <a class="nav-link" href="posts.php">
                        <i class="fas fa-file-alt"></i>
                        Posts
                    </a>
                </li>
                <?php endif; ?>
                
                <?php if (hasPermission('manage_categories')): ?>
                <li class="nav-item">
                    <a class="nav-link" href="categories.php">
                        <i class="fas fa-tags"></i>
                        Categories
                    </a>
                </li>
                <?php endif; ?>
                
                <?php if (hasPermission('manage_comments')): ?>
                <li class="nav-item">
                    <a class="nav-link" href="comments.php">
                        <i class="fas fa-comments"></i>
                        Comments
                        <?php if (isset($stats['pending_comments']) && $stats['pending_comments'] > 0): ?>
                        <span class="badge bg-warning ms-auto"><?php echo $stats['pending_comments']; ?></span>
                        <?php endif; ?>
                    </a>
                </li>
                <?php endif; ?>
                
                <?php if (hasPermission('manage_users')): ?>
                <li class="nav-item">
                    <a class="nav-link" href="users.php">
                        <i class="fas fa-users"></i>
                        Users
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="register.php">
                        <i class="fas fa-user-plus"></i>
                        Add User
                    </a>
                </li>
                <?php endif; ?>
                
                <?php if (hasPermission('manage_settings')): ?>
                <li class="nav-item">
                    <a class="nav-link" href="settings.php">
                        <i class="fas fa-cog"></i>
                        Settings
                    </a>
                </li>
                <?php endif; ?>
            </ul>
        </nav>
    </div>

    <!-- Main Content -->
    <div class="main-content">
        <!-- Top Bar -->
        <div class="topbar">
            <div class="d-flex align-items-center">
                <button class="btn btn-light d-md-none me-3" id="sidebarToggle">
                    <i class="fas fa-bars"></i>
                </button>
                <h4 class="mb-0">Dashboard</h4>
            </div>
            
            <div class="d-flex align-items-center">
                <?php if (isset($_GET['error']) && $_GET['error'] === 'access_denied'): ?>
                <div class="alert alert-warning alert-sm me-3 mb-0 py-2 px-3">
                    <i class="fas fa-exclamation-triangle me-1"></i>
                    Access denied
                </div>
                <?php endif; ?>
                
                <div class="dropdown user-menu">
                    <a class="btn btn-light dropdown-toggle d-flex align-items-center" 
                       href="#" role="button" data-bs-toggle="dropdown" aria-expanded="false">
                        <i class="fas fa-user-circle me-2"></i>
                        <?php echo htmlspecialchars($current_user['username']); ?>
                    </a>
                    <ul class="dropdown-menu dropdown-menu-end">
                        <li>
                            <h6 class="dropdown-header">
                                <i class="fas fa-user me-2"></i>
                                <?php echo htmlspecialchars($current_user['username']); ?>
                            </h6>
                        </li>
                        <li>
                            <span class="dropdown-item-text">
                                <small class="text-muted">
                                    Role: <?php echo ucfirst($current_user['role']); ?>
                                </small>
                            </span>
                        </li>
                        <li><hr class="dropdown-divider"></li>
                        <li>
                            <a class="dropdown-item" href="profile.php">
                                <i class="fas fa-user-edit me-2"></i>
                                Profile
                            </a>
                        </li>
                        <li>
                            <a class="dropdown-item" href="logout.php">
                                <i class="fas fa-sign-out-alt me-2"></i>
                                Logout
                            </a>
                        </li>
                    </ul>
                </div>
            </div>
        </div>

        <!-- Content Area -->
        <div class="content-area">
            <!-- Welcome Section -->
            <div class="welcome-section">
                <div class="row align-items-center">
                    <div class="col-md-8">
                        <h2 class="mb-2">
                            <i class="fas fa-wave-square me-2"></i>
                            Welcome back, <?php echo htmlspecialchars($current_user['username']); ?>!
                        </h2>
                        <p class="mb-0 opacity-75">
                            You're logged in as <strong><?php echo ucfirst($current_user['role']); ?></strong>. 
                            Here's your dashboard overview.
                        </p>
                    </div>
                    <div class="col-md-4 text-end">
                        <div class="fs-1 opacity-50">
                            <i class="fas fa-chart-line"></i>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Dashboard Stats -->
            <div class="row mb-4">
                <div class="col-lg-3 col-md-6 mb-4">
                    <div class="card stats-card">
                        <div class="card-body p-4">
                            <div class="d-flex align-items-center">
                                <div class="stats-icon bg-primary me-3">
                                    <i class="fas fa-file-alt"></i>
                                </div>
                                <div>
                                    <h3 class="mb-0 fw-bold"><?php echo $stats['total_posts'] ?? 0; ?></h3>
                                    <p class="text-muted mb-0">
                                        <?php echo $current_user['role'] === 'admin' ? 'Total Posts' : 'My Posts'; ?>
                                    </p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="col-lg-3 col-md-6 mb-4">
                    <div class="card stats-card">
                        <div class="card-body p-4">
                            <div class="d-flex align-items-center">
                                <div class="stats-icon bg-success me-3">
                                    <i class="fas fa-check-circle"></i>
                                </div>
                                <div>
                                    <h3 class="mb-0 fw-bold"><?php echo $stats['published_posts'] ?? 0; ?></h3>
                                    <p class="text-muted mb-0">Published</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <?php if (hasPermission('manage_comments')): ?>
                <div class="col-lg-3 col-md-6 mb-4">
                    <div class="card stats-card">
                        <div class="card-body p-4">
                            <div class="d-flex align-items-center">
                                <div class="stats-icon bg-info me-3">
                                    <i class="fas fa-comments"></i>
                                </div>
                                <div>
                                    <h3 class="mb-0 fw-bold"><?php echo $stats['total_comments'] ?? 0; ?></h3>
                                    <p class="text-muted mb-0">Comments</p>
                                    <?php if (isset($stats['pending_comments']) && $stats['pending_comments'] > 0): ?>
                                    <small class="text-warning">
                                        <i class="fas fa-clock me-1"></i>
                                        <?php echo $stats['pending_comments']; ?> pending
                                    </small>
                                    <?php endif; ?>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <?php endif; ?>
                
                <?php if (hasPermission('manage_users')): ?>
                <div class="col-lg-3 col-md-6 mb-4">
                    <div class="card stats-card">
                        <div class="card-body p-4">
                            <div class="d-flex align-items-center">
                                <div class="stats-icon bg-warning me-3">
                                    <i class="fas fa-users"></i>
                                </div>
                                <div>
                                    <h3 class="mb-0 fw-bold"><?php echo $stats['total_users'] ?? 0; ?></h3>
                                    <p class="text-muted mb-0">Active Users</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <?php endif; ?>
            </div>

            <!-- Main Content Row -->
            <div class="row">
                <!-- Recent Posts -->
                <div class="col-lg-8 mb-4">
                    <div class="card">
                        <div class="card-header d-flex justify-content-between align-items-center">
                            <h5 class="mb-0">
                                <i class="fas fa-clock me-2"></i>
                                Recent Posts
                            </h5>
                            <?php if (hasPermission('create_post')): ?>
                            <a href="posts.php?action=create" class="btn btn-primary btn-sm">
                                <i class="fas fa-plus me-1"></i>
                                New Post
                            </a>
                            <?php endif; ?>
                        </div>
                        <div class="card-body">
                            <?php if (!empty($recent_posts)): ?>
                            <div class="table-responsive">
                                <table class="table table-hover">
                                    <thead>
                                        <tr>
                                            <th>Title</th>
                                            <th>Author</th>
                                            <th>Status</th>
                                            <th>Created</th>
                                            <th>Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($recent_posts as $post): ?>
                                        <tr>
                                            <td>
                                                <strong><?php echo htmlspecialchars($post['title']); ?></strong>
                                            </td>
                                            <td>
                                                <i class="fas fa-user-circle me-1"></i>
                                                <?php echo htmlspecialchars($post['author']); ?>
                                            </td>
                                            <td>
                                                <?php
                                                $status_class = '';
                                                $status_icon = '';
                                                switch ($post['status']) {
                                                    case 'published':
                                                        $status_class = 'success';
                                                        $status_icon = 'fas fa-check-circle';
                                                        break;
                                                    case 'draft':
                                                        $status_class = 'warning';
                                                        $status_icon = 'fas fa-edit';
                                                        break;
                                                    case 'archived':
                                                        $status_class = 'secondary';
                                                        $status_icon = 'fas fa-archive';
                                                        break;
                                                }
                                                ?>
                                                <span class="badge bg-<?php echo $status_class; ?>">
                                                    <i class="<?php echo $status_icon; ?> me-1"></i>
                                                    <?php echo ucfirst($post['status']); ?>
                                                </span>
                                            </td>
                                            <td>
                                                <small class="text-muted">
                                                    <i class="fas fa-calendar me-1"></i>
                                                    <?php echo date('M j, Y', strtotime($post['created_at'])); ?>
                                                </small>
                                            </td>
                                            <td>
                                                <?php if (canEditPost($post['id'])): ?>
                                                <a href="posts.php?action=edit&id=<?php echo $post['id']; ?>" 
                                                   class="btn btn-sm btn-outline-primary" 
                                                   title="Edit Post">
                                                    <i class="fas fa-edit"></i>
                                                </a>
                                                <?php endif; ?>
                                                <a href="posts.php?action=view&id=<?php echo $post['id']; ?>" 
                                                   class="btn btn-sm btn-outline-secondary ms-1" 
                                                   title="View Post">
                                                    <i class="fas fa-eye"></i>
                                                </a>
                                            </td>
                                        </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                            <?php else: ?>
                            <div class="text-center py-5">
                                <i class="fas fa-file-alt text-muted fa-4x mb-3"></i>
                                <h5 class="text-muted">No posts yet</h5>
                                <p class="text-muted">
                                    <?php echo $current_user['role'] === 'admin' ? 'No posts have been created yet.' : 'Start by creating your first post.'; ?>
                                </p>
                                <?php if (hasPermission('create_post')): ?>
                                <a href="posts.php?action=create" class="btn btn-primary">
                                    <i class="fas fa-plus me-1"></i>
                                    Create Your First Post
                                </a>
                                <?php endif; ?>
                            </div>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>

                <!-- Sidebar Info -->
                <div class="col-lg-4 mb-4">
                    <!-- Quick Info Card -->
                    <div class="card mb-4">
                        <div class="card-header">
                            <h5 class="mb-0">
                                <i class="fas fa-info-circle me-2"></i>
                                Quick Info
                            </h5>
                        </div>
                        <div class="card-body">
                            <div class="mb-3">
                                <h6 class="text-muted">Account Details</h6>
                                <p class="mb-1">
                                    <strong><?php echo htmlspecialchars($current_user['username']); ?></strong>
                                </p>
                                <small class="text-muted">
                                    <i class="fas fa-envelope me-1"></i>
                                    <?php echo htmlspecialchars($current_user['email']); ?>
                                </small><br>
                                <small class="text-muted">
                                    <i class="fas fa-user-tag me-1"></i>
                                    Role: <?php echo ucfirst($current_user['role']); ?>
                                </small>
                            </div>
                            
                            <hr>
                            
                            <div class="mb-3">
                                <h6 class="text-muted">Your Permissions</h6>
                                <div class="d-flex flex-wrap gap-1">
                                    <?php
                                    $user_permissions = [];
                                    if (hasPermission('create_post')) $user_permissions[] = 'Create Posts';
                                    if (hasPermission('edit_any_post')) $user_permissions[] = 'Edit All Posts';
                                    elseif (hasPermission('edit_own_post')) $user_permissions[] = 'Edit Own Posts';
                                    if (hasPermission('manage_users')) $user_permissions[] = 'Manage Users';
                                    if (hasPermission('manage_categories')) $user_permissions[] = 'Manage Categories';
                                    if (hasPermission('manage_comments')) $user_permissions[] = 'Manage Comments';
                                    if (hasPermission('manage_settings')) $user_permissions[] = 'Manage Settings';
                                    
                                    foreach ($user_permissions as $permission):
                                    ?>
                                    <span class="badge bg-light text-dark border"><?php echo $permission; ?></span>
                                    <?php endforeach; ?>
                                </div>
                            </div>
                            
                            <hr>
                            
                            <div>
                                <h6 class="text-muted">Quick Actions</h6>
                                <div class="d-grid gap-2">
                                    <?php if (hasPermission('create_post')): ?>
                                    <a href="posts.php?action=create" class="btn btn-outline-primary btn-sm">
                                        <i class="fas fa-plus me-1"></i>
                                        New Post
                                    </a>
                                    <?php endif; ?>
                                    
                                    <?php if (hasPermission('manage_users')): ?>
                                    <a href="register.php" class="btn btn-outline-success btn-sm">
                                        <i class="fas fa-user-plus me-1"></i>
                                        Add User
                                    </a>
                                    <?php endif; ?>
                                    
                                    <a href="profile.php" class="btn btn-outline-secondary btn-sm">
                                        <i class="fas fa-user-edit me-1"></i>
                                        Edit Profile
                                    </a>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- System Status Card -->
                    <div class="card">
                        <div class="card-header">
                            <h5 class="mb-0">
                                <i class="fas fa-server me-2"></i>
                                System Status
                            </h5>
                        </div>
                        <div class="card-body">
                            <div class="row g-3">
                                <div class="col-6">
                                    <small class="text-muted">PHP Version</small>
                                    <div class="fw-bold"><?php echo PHP_VERSION; ?></div>
                                </div>
                                <div class="col-6">
                                    <small class="text-muted">Server Time</small>
                                    <div class="fw-bold current-time"><?php echo date('H:i:s'); ?></div>
                                </div>
                                <div class="col-6">
                                    <small class="text-muted">Memory Usage</small>
                                    <div class="fw-bold"><?php echo round(memory_get_usage(true) / 1024 / 1024, 2); ?> MB</div>
                                </div>
                                <div class="col-6">
                                    <small class="text-muted">Session</small>
                                    <div class="fw-bold">
                                        <span class="text-success">
                                            <i class="fas fa-circle" style="font-size: 0.5rem;"></i>
                                            Active
                                        </span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Recent Activity Section (Full Width) -->
            <?php if (hasPermission('manage_users') || hasPermission('manage_comments')): ?>
            <div class="row mt-4">
                <div class="col-12">
                    <div class="card">
                        <div class="card-header">
                            <h5 class="mb-0">
                                <i class="fas fa-history me-2"></i>
                                Recent Activity
                            </h5>
                        </div>
                        <div class="card-body">
                            <div class="row">
                                <?php if (hasPermission('manage_users')): ?>
                                <div class="col-md-6">
                                    <h6 class="text-muted mb-3">
                                        <i class="fas fa-users me-1"></i>
                                        Recent Users
                                    </h6>
                                    <?php
                                    $connection = getConnection();
                                    try {
                                        $recent_users_query = "SELECT username, role, created_at FROM users ORDER BY created_at DESC LIMIT 5";
                                        $users_stmt = executePreparedStatement($connection, $recent_users_query);
                                        $users_result = getPreparedResult($users_stmt);
                                        
                                        if ($users_result->num_rows > 0):
                                            while ($user = $users_result->fetch_assoc()):
                                    ?>
                                    <div class="d-flex justify-content-between align-items-center mb-2 p-2 bg-light rounded">
                                        <div>
                                            <strong><?php echo htmlspecialchars($user['username']); ?></strong>
                                            <span class="badge bg-secondary ms-2"><?php echo ucfirst($user['role']); ?></span>
                                        </div>
                                        <small class="text-muted"><?php echo date('M j', strtotime($user['created_at'])); ?></small>
                                    </div>
                                    <?php 
                                            endwhile;
                                        else:
                                    ?>
                                    <p class="text-muted">No recent users</p>
                                    <?php endif; ?>
                                    <?php
                                        $users_stmt->close();
                                    } catch (Exception $e) {
                                        echo '<p class="text-muted">Unable to load recent users</p>';
                                    }
                                    ?>
                                </div>
                                <?php endif; ?>
                                
                                <?php if (hasPermission('manage_comments')): ?>
                                <div class="col-md-6">
                                    <h6 class="text-muted mb-3">
                                        <i class="fas fa-comments me-1"></i>
                                        Recent Comments
                                    </h6>
                                    <?php
                                    try {
                                        $recent_comments_query = "SELECT c.author_name, c.content, c.status, c.created_at, p.title 
                                                                FROM comments c 
                                                                JOIN posts p ON c.post_id = p.id 
                                                                ORDER BY c.created_at DESC 
                                                                LIMIT 5";
                                        $comments_stmt = executePreparedStatement($connection, $recent_comments_query);
                                        $comments_result = getPreparedResult($comments_stmt);
                                        
                                        if ($comments_result->num_rows > 0):
                                            while ($comment = $comments_result->fetch_assoc()):
                                    ?>
                                    <div class="mb-3 p-2 bg-light rounded">
                                        <div class="d-flex justify-content-between align-items-start">
                                            <div class="flex-grow-1">
                                                <strong><?php echo htmlspecialchars($comment['author_name']); ?></strong>
                                                <span class="badge bg-<?php echo $comment['status'] === 'approved' ? 'success' : ($comment['status'] === 'pending' ? 'warning' : 'danger'); ?> ms-2">
                                                    <?php echo ucfirst($comment['status']); ?>
                                                </span>
                                                <div class="small text-muted mt-1">
                                                    on "<?php echo htmlspecialchars(substr($comment['title'], 0, 30)); ?>..."
                                                </div>
                                                <div class="small mt-1">
                                                    <?php echo htmlspecialchars(substr($comment['content'], 0, 50)); ?>...
                                                </div>
                                            </div>
                                            <small class="text-muted"><?php echo date('M j', strtotime($comment['created_at'])); ?></small>
                                        </div>
                                    </div>
                                    <?php 
                                            endwhile;
                                        else:
                                    ?>
                                    <p class="text-muted">No recent comments</p>
                                    <?php endif; ?>
                                    <?php
                                        $comments_stmt->close();
                                    } catch (Exception $e) {
                                        echo '<p class="text-muted">Unable to load recent comments</p>';
                                    }
                                    closeConnection($connection);
                                    ?>
                                </div>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <?php endif; ?>
            
            <!-- Footer -->
            <div class="row mt-5">
                <div class="col-12">
                    <div class="text-center text-muted py-4">
                        <hr>
                        <small>
                            © <?php echo date('Y'); ?> Blog Admin Panel. 
                            Logged in as <strong><?php echo htmlspecialchars($current_user['username']); ?></strong> 
                            (<?php echo ucfirst($current_user['role']); ?>)
                            | Session started: <?php echo date('H:i:s'); ?>
                        </small>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/js/bootstrap.bundle.min.js"></script>
    <script>
        // Sidebar toggle for mobile
        document.getElementById('sidebarToggle')?.addEventListener('click', function() {
            document.querySelector('.sidebar').classList.toggle('show');
        });

        // Close sidebar when clicking outside on mobile
        document.addEventListener('click', function(e) {
            const sidebar = document.querySelector('.sidebar');
            const toggle = document.getElementById('sidebarToggle');
            
            if (window.innerWidth <= 768 && sidebar && sidebar.classList.contains('show')) {
                if (!sidebar.contains(e.target) && !toggle?.contains(e.target)) {
                    sidebar.classList.remove('show');
                }
            }
        });

        // Active navigation highlighting
        const currentPage = window.location.pathname.split('/').pop();
        const navLinks = document.querySelectorAll('.nav-link');
        
        navLinks.forEach(link => {
            const href = link.getAttribute('href');
            if (href === currentPage || (currentPage === '' && href === 'dashboard.php')) {
                link.classList.add('active');
            } else {
                link.classList.remove('active');
            }
        });

        // Auto-hide alerts
        setTimeout(function() {
            const alerts = document.querySelectorAll('.alert');
            alerts.forEach(alert => {
                if (alert.classList.contains('alert-warning')) {
                    alert.style.transition = 'opacity 0.5s';
                    alert.style.opacity = '0';
                    setTimeout(() => alert.remove(), 500);
                }
            });
        }, 3000);

        // Real-time clock update
        function updateClock() {
            const now = new Date();
            const timeString = now.toLocaleTimeString();
            const clockElements = document.querySelectorAll('.current-time');
            clockElements.forEach(element => {
                element.textContent = timeString;
            });
        }

        // Update clock every second
        setInterval(updateClock, 1000);

        // Add loading states for buttons
        document.querySelectorAll('a.btn').forEach(button => {
            button.addEventListener('click', function() {
                if (!this.classList.contains('btn-outline-secondary')) {
                    const originalText = this.innerHTML;
                    this.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Loading...';
                    setTimeout(() => {
                        this.innerHTML = originalText;
                    }, 2000);
                }
            });
        });

        // Add hover effects for stats cards
        document.querySelectorAll('.stats-card').forEach(card => {
            card.addEventListener('mouseenter', function() {
                this.style.transform = 'translateY(-8px)';
            });
            
            card.addEventListener('mouseleave', function() {
                this.style.transform = 'translateY(0px)';
            });
        });

        // Initialize tooltips if Bootstrap tooltip is available
        if (typeof bootstrap !== 'undefined' && bootstrap.Tooltip) {
            const tooltipTriggerList = [].slice.call(document.querySelectorAll('[title]'));
            const tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
                return new bootstrap.Tooltip(tooltipTriggerEl);
            });
        }

        // Smooth scrolling for anchor links
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({
                        behavior: 'smooth'
                    });
                }
            });
        });

        // Console log for debugging (remove in production)
        console.log('Dashboard loaded for user:', '<?php echo $current_user['username']; ?>');
        console.log('User role:', '<?php echo $current_user['role']; ?>');
        console.log('User permissions:', {
            create_post: <?php echo hasPermission('create_post') ? 'true' : 'false'; ?>,
            manage_users: <?php echo hasPermission('manage_users') ? 'true' : 'false'; ?>,
            manage_comments: <?php echo hasPermission('manage_comments') ? 'true' : 'false'; ?>,
            manage_settings: <?php echo hasPermission('manage_settings') ? 'true' : 'false'; ?>
        });

        // Page load animation
        document.addEventListener('DOMContentLoaded', function() {
            document.body.style.opacity = '0';
            document.body.style.transition = 'opacity 0.3s';
            setTimeout(() => {
                document.body.style.opacity = '1';
            }, 100);
        });
    </script>
</body>
</html>