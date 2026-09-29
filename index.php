<?php
/**
 * Scholarship Portal - Full Visual Edition with Images
 */
session_start();
require_once 'config.php';

// ==================== SECURITY HELPERS ====================
function csrf_token() { if (empty($_SESSION['csrf_token'])) $_SESSION['csrf_token'] = bin2hex(random_bytes(32)); return $_SESSION['csrf_token']; }
function verify_csrf($t) { return !empty($_SESSION['csrf_token']) && !empty($t) && hash_equals($_SESSION['csrf_token'], $t); }
function e($s) { return htmlspecialchars($s ?? '', ENT_QUOTES, 'UTF-8'); }
function flash($m, $t='success') { $_SESSION['message']=$m; $_SESSION['message_type']=$t; }
function redirect($u) { header("Location: $u"); exit(); }

// Country flag emoji mapper
function country_flag($country) {
    $map = [
        'usa'=>'🇺🇸','united states'=>'🇺🇸','uk'=>'🇬🇧','united kingdom'=>'🇬🇧','england'=>'🇬🇧',
        'canada'=>'🇨🇦','australia'=>'🇦🇺','germany'=>'🇩🇪','france'=>'🇫🇷','italy'=>'🇮🇹',
        'japan'=>'🇯🇵','china'=>'🇨🇳','india'=>'🇮🇳','pakistan'=>'🇵🇰','turkey'=>'🇹🇷',
        'sweden'=>'🇸🇪','norway'=>'🇳🇴','netherlands'=>'🇳🇱','switzerland'=>'🇨🇭','singapore'=>'🇸🇬',
        'south korea'=>'🇰🇷','korea'=>'🇰🇷','new zealand'=>'🇳🇿','ireland'=>'🇮🇪','spain'=>'🇪🇸',
        'brazil'=>'🇧🇷','russia'=>'🇷🇺','uae'=>'🇦🇪','saudi arabia'=>'🇸🇦','malaysia'=>'🇲🇾',
    ];
    $key = strtolower(trim($country));
    return $map[$key] ?? '🌍';
}

function initials($name) {
    $parts = preg_split('/\s+/', trim($name));
    $i = '';
    foreach (array_slice($parts,0,2) as $p) $i .= strtoupper(substr($p,0,1));
    return $i ?: '?';
}

// ==================== DATABASE ====================
function getDBConnection() {
    try {
        $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
        if ($conn->connect_error) die("Connection failed: ".$conn->connect_error);
        $conn->set_charset('utf8mb4');
        return $conn;
    } catch (Exception $e) { die("Database error: ".$e->getMessage()); }
}

function initializeDatabase() {
    $conn = getDBConnection();
    $conn->query("CREATE TABLE IF NOT EXISTS users (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(100) NOT NULL, email VARCHAR(100) UNIQUE NOT NULL, cnic VARCHAR(15) UNIQUE NOT NULL, password VARCHAR(255) NOT NULL DEFAULT '', user_type ENUM('student','admin') DEFAULT 'student', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
    $conn->query("CREATE TABLE IF NOT EXISTS student_profiles (id INT AUTO_INCREMENT PRIMARY KEY, user_id INT NOT NULL, degree_level VARCHAR(50) NOT NULL, degree_name VARCHAR(100) NOT NULL, institute VARCHAR(200) NOT NULL, year VARCHAR(10) NOT NULL, percentage DECIMAL(5,2) NOT NULL, grade VARCHAR(5), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)");
    $conn->query("CREATE TABLE IF NOT EXISTS scholarships (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(200) NOT NULL, institute VARCHAR(200) NOT NULL, country VARCHAR(100) NOT NULL, degree_level VARCHAR(50) NOT NULL, benefits TEXT NOT NULL, requirements TEXT NOT NULL, min_percentage DECIMAL(5,2), deadline DATE NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
    $conn->query("CREATE TABLE IF NOT EXISTS applications (id INT AUTO_INCREMENT PRIMARY KEY, user_id INT NOT NULL, scholarship_id INT NOT NULL, status ENUM('pending','approved','rejected') DEFAULT 'pending', applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, UNIQUE KEY unique_app (user_id, scholarship_id), FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE, FOREIGN KEY (scholarship_id) REFERENCES scholarships(id) ON DELETE CASCADE)");
    $col = $conn->query("SHOW COLUMNS FROM users LIKE 'password'");
    if ($col && $col->num_rows === 0) $conn->query("ALTER TABLE users ADD COLUMN password VARCHAR(255) NOT NULL DEFAULT '' AFTER cnic");
    $col = $conn->query("SHOW COLUMNS FROM scholarships LIKE 'deadline'");
    if ($col && $col->num_rows === 0) $conn->query("ALTER TABLE scholarships ADD COLUMN deadline DATE NULL AFTER min_percentage");
    $admin = $conn->query("SELECT id FROM users WHERE email='admin@scholarship.com'");
    if ($admin->num_rows === 0) {
        $h=password_hash('admin123',PASSWORD_DEFAULT);
        $s=$conn->prepare("INSERT INTO users (name,email,cnic,password,user_type) VALUES (?,?,?,?,'admin')");
        $n='Admin'; $em='admin@scholarship.com'; $c='00000-0000000-0';
        $s->bind_param('ssss',$n,$em,$c,$h); $s->execute(); $s->close();
    } else {
        $row=$admin->fetch_assoc();
        $c=$conn->query("SELECT password FROM users WHERE id={$row['id']}");
        if (empty($c->fetch_assoc()['password'])) {
            $h=password_hash('admin123',PASSWORD_DEFAULT);
            $s=$conn->prepare("UPDATE users SET password=? WHERE id=?");
            $s->bind_param('si',$h,$row['id']); $s->execute(); $s->close();
        }
    }
    $conn->close();
}
initializeDatabase();

// ==================== POST HANDLERS ====================
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    if ($action !== 'logout' && !verify_csrf($_POST['csrf_token'] ?? '')) { flash('Invalid request.','error'); redirect($_SERVER['PHP_SELF']); }
    switch ($action) {
        case 'register':           handleRegister();          break;
        case 'login':              handleLogin();             break;
        case 'logout':             handleLogout();            break;
        case 'add_profile':        handleAddProfile();        break;
        case 'update_profile':     handleUpdateProfile();     break;
        case 'delete_profile':     handleDeleteProfile();     break;
        case 'add_scholarship':    handleAddScholarship();    break;
        case 'update_scholarship': handleUpdateScholarship(); break;
        case 'delete_scholarship': handleDeleteScholarship(); break;
        case 'apply':              handleApply();             break;
        case 'delete_user':        handleDeleteUser();        break;
        case 'reset_password':     handleResetPassword();     break;
        case 'toggle_role':        handleToggleUserRole();    break;
        case 'update_application': handleUpdateApplication(); break;
    }
}

function handleRegister() {
    $conn=getDBConnection();
    $n=trim($_POST['name']??''); $e=trim($_POST['email']??''); $c=trim($_POST['cnic']??''); $p=$_POST['password']??'';
    if (strlen($p)<6) { flash('Password must be 6+ chars.','error'); $conn->close(); redirect('?page=register'); }
    $s=$conn->prepare("SELECT id FROM users WHERE email=? OR cnic=? LIMIT 1");
    $s->bind_param('ss',$e,$c); $s->execute();
    if ($s->get_result()->num_rows>0) { flash('Email or CNIC already used.','error'); $s->close(); $conn->close(); redirect('?page=register'); }
    $s->close();
    $h=password_hash($p,PASSWORD_DEFAULT);
    $s=$conn->prepare("INSERT INTO users (name,email,cnic,password) VALUES (?,?,?,?)");
    $s->bind_param('ssss',$n,$e,$c,$h);
    if ($s->execute()) { flash('Registration successful!','success'); redirect('?page=login'); }
    flash('Failed: '.$conn->error,'error'); redirect('?page=register');
}

function handleLogin() {
    $conn=getDBConnection();
    $e=trim($_POST['email']??''); $p=$_POST['password']??'';
    $s=$conn->prepare("SELECT id,name,password,user_type FROM users WHERE email=? LIMIT 1");
    $s->bind_param('s',$e); $s->execute(); $r=$s->get_result();
    if ($r->num_rows===0) { flash('Invalid credentials.','error'); $s->close(); $conn->close(); redirect('?page=login'); }
    $u=$r->fetch_assoc(); $s->close(); $conn->close();
    if (!password_verify($p,$u['password'])) { flash('Invalid credentials.','error'); redirect('?page=login'); }
    session_regenerate_id(true);
    $_SESSION['user_id']=$u['id']; $_SESSION['user_name']=$u['name']; $_SESSION['user_type']=$u['user_type'];
    flash('Welcome back, '.e($u['name']).'!','success'); redirect('?page=home');
}

function handleLogout() {
    $_SESSION=[];
    if (ini_get("session.use_cookies")) { $p=session_get_cookie_params(); setcookie(session_name(),'',time()-42000,$p["path"],$p["domain"],$p["secure"],$p["httponly"]); }
    session_destroy();
    header("Location: ".$_SERVER['PHP_SELF']); exit();
}

function handleAddProfile() {
    if (empty($_SESSION['user_id'])) redirect('?page=login');
    $conn=getDBConnection(); $uid=(int)$_SESSION['user_id'];
    $s=$conn->prepare("INSERT INTO student_profiles (user_id,degree_level,degree_name,institute,year,percentage,grade) VALUES (?,?,?,?,?,?,?)");
    $s->bind_param('issssds',$uid,$_POST['degree_level'],$_POST['degree_name'],$_POST['institute'],$_POST['year'],(float)$_POST['percentage'],$_POST['grade']);
    $s->execute()?flash('Record added!','success'):flash('Error: '.$conn->error,'error');
    $s->close(); $conn->close(); redirect('?page=profile');
}

function handleUpdateProfile() {
    if (empty($_SESSION['user_id'])) redirect('?page=login');
    $conn=getDBConnection();
    $s=$conn->prepare("UPDATE student_profiles SET degree_level=?,degree_name=?,institute=?,year=?,percentage=?,grade=? WHERE id=? AND user_id=?");
    $pid=(int)$_POST['profile_id']; $uid=(int)$_SESSION['user_id'];
    $s->bind_param('ssssdsii',$_POST['degree_level'],$_POST['degree_name'],$_POST['institute'],$_POST['year'],(float)$_POST['percentage'],$_POST['grade'],$pid,$uid);
    $s->execute()?flash('Updated!','success'):flash('Error: '.$conn->error,'error');
    $s->close(); $conn->close(); redirect('?page=profile');
}

function handleDeleteProfile() {
    if (empty($_SESSION['user_id'])) redirect('?page=login');
    $conn=getDBConnection();
    $s=$conn->prepare("DELETE FROM student_profiles WHERE id=? AND user_id=?");
    $pid=(int)$_POST['profile_id']; $uid=(int)$_SESSION['user_id'];
    $s->bind_param('ii',$pid,$uid); $s->execute(); $s->close(); $conn->close();
    flash('Deleted.','success'); redirect('?page=profile');
}

function handleAddScholarship() {
    if (($_SESSION['user_type']??'')!=='admin') redirect('?page=home');
    $conn=getDBConnection();
    $s=$conn->prepare("INSERT INTO scholarships (name,institute,country,degree_level,benefits,requirements,min_percentage,deadline) VALUES (?,?,?,?,?,?,?,?)");
    $dl=!empty($_POST['deadline'])?$_POST['deadline']:null;
    $s->bind_param('ssssssds',$_POST['name'],$_POST['institute'],$_POST['country'],$_POST['degree_level'],$_POST['benefits'],$_POST['requirements'],(float)$_POST['min_percentage'],$dl);
    $s->execute()?flash('Scholarship added!','success'):flash('Error: '.$conn->error,'error');
    $s->close(); $conn->close(); redirect('?page=admin&tab=scholarships');
}

function handleUpdateScholarship() {
    if (($_SESSION['user_type']??'')!=='admin') redirect('?page=home');
    $conn=getDBConnection();
    $s=$conn->prepare("UPDATE scholarships SET name=?,institute=?,country=?,degree_level=?,benefits=?,requirements=?,min_percentage=?,deadline=? WHERE id=?");
    $dl=!empty($_POST['deadline'])?$_POST['deadline']:null; $sid=(int)$_POST['scholarship_id'];
    $s->bind_param('ssssssdsi',$_POST['name'],$_POST['institute'],$_POST['country'],$_POST['degree_level'],$_POST['benefits'],$_POST['requirements'],(float)$_POST['min_percentage'],$dl,$sid);
    $s->execute()?flash('Updated!','success'):flash('Error: '.$conn->error,'error');
    $s->close(); $conn->close(); redirect('?page=admin&tab=scholarships');
}

function handleDeleteScholarship() {
    if (($_SESSION['user_type']??'')!=='admin') redirect('?page=home');
    $conn=getDBConnection();
    $s=$conn->prepare("DELETE FROM scholarships WHERE id=?"); $sid=(int)$_POST['scholarship_id'];
    $s->bind_param('i',$sid); $s->execute(); $s->close(); $conn->close();
    flash('Deleted.','success'); redirect('?page=admin&tab=scholarships');
}

function handleApply() {
    if (empty($_SESSION['user_id'])) redirect('?page=login');
    $conn=getDBConnection();
    $uid=(int)$_SESSION['user_id']; $sid=(int)$_POST['scholarship_id'];
    $s=$conn->prepare("INSERT IGNORE INTO applications (user_id,scholarship_id) VALUES (?,?)");
    $s->bind_param('ii',$uid,$sid); $s->execute();
    ($s->affected_rows>0)?flash('Application submitted!','success'):flash('Already applied.','error');
    $s->close(); $conn->close(); redirect('?page=scholarships');
}

function handleDeleteUser() {
    if (($_SESSION['user_type']??'')!=='admin') redirect('?page=home');
    $conn=getDBConnection(); $uid=(int)$_POST['user_id'];
    if ($uid===(int)$_SESSION['user_id']) flash('Cannot delete yourself.','error');
    else { $s=$conn->prepare("DELETE FROM users WHERE id=? AND user_type!='admin'"); $s->bind_param('i',$uid); $s->execute(); $s->close(); flash('User deleted.','success'); }
    $conn->close(); redirect('?page=admin&tab=users');
}

function handleResetPassword() {
    if (($_SESSION['user_type']??'')!=='admin') { flash('Admin access required.','error'); redirect('?page=home'); }
    $conn=getDBConnection(); $uid=(int)($_POST['user_id']??0); $newPass=$_POST['new_password']??'';
    if (strlen($newPass)<6) { flash('Password must be 6+ chars.','error'); $conn->close(); redirect('?page=admin&tab=users'); }
    $check=$conn->prepare("SELECT name FROM users WHERE id=?"); $check->bind_param('i',$uid); $check->execute();
    $row=$check->get_result()->fetch_assoc(); $check->close();
    if (!$row) flash('User not found.','error');
    else {
        $h=password_hash($newPass,PASSWORD_DEFAULT);
        $s=$conn->prepare("UPDATE users SET password=? WHERE id=?"); $s->bind_param('si',$h,$uid); $s->execute(); $s->close();
        flash('✅ Password reset for <strong>'.e($row['name']).'</strong>','success');
    }
    $conn->close(); redirect('?page=admin&tab=users');
}

function handleToggleUserRole() {
    if (($_SESSION['user_type']??'')!=='admin') { flash('Admin access required.','error'); redirect('?page=home'); }
    $conn=getDBConnection(); $uid=(int)($_POST['user_id']??0);
    if ($uid===(int)$_SESSION['user_id']) { flash('You cannot change your own role.','error'); $conn->close(); redirect('?page=admin&tab=users'); }
    $s=$conn->prepare("SELECT user_type FROM users WHERE id=?"); $s->bind_param('i',$uid); $s->execute();
    $u=$s->get_result()->fetch_assoc(); $s->close();
    if ($u) {
        $newRole=$u['user_type']==='admin'?'student':'admin';
        $s=$conn->prepare("UPDATE users SET user_type=? WHERE id=?"); $s->bind_param('si',$newRole,$uid); $s->execute(); $s->close();
        flash("Role changed to <strong>".e($newRole)."</strong>",'success');
    }
    $conn->close(); redirect('?page=admin&tab=users');
}

function handleUpdateApplication() {
    if (($_SESSION['user_type']??'')!=='admin') { flash('Admin access required.','error'); redirect('?page=home'); }
    $conn=getDBConnection(); $appId=(int)($_POST['application_id']??0); $status=$_POST['status']??'pending';
    if (!in_array($status,['pending','approved','rejected'],true)) { flash('Invalid status.','error'); $conn->close(); redirect('?page=admin&tab=applications'); }
    $s=$conn->prepare("UPDATE applications SET status=? WHERE id=?"); $s->bind_param('si',$status,$appId); $s->execute(); $s->close(); $conn->close();
    flash('Application marked as <strong>'.e($status).'</strong>.','success'); redirect('?page=admin&tab=applications');
}

// ==================== FETCH HELPERS ====================
function getUserProfiles($uid) {
    $c=getDBConnection(); $s=$c->prepare("SELECT * FROM student_profiles WHERE user_id=? ORDER BY year DESC");
    $s->bind_param('i',$uid); $s->execute(); $r=$s->get_result()->fetch_all(MYSQLI_ASSOC);
    $s->close(); $c->close(); return $r;
}
function getAllScholarships() {
    $c=getDBConnection(); $r=$c->query("SELECT * FROM scholarships ORDER BY created_at DESC")->fetch_all(MYSQLI_ASSOC);
    $c->close(); return $r;
}
function searchScholarships($n,$co,$d) {
    $c=getDBConnection(); $sql="SELECT * FROM scholarships WHERE 1=1"; $p=[]; $t='';
    if ($n!=='')  { $sql.=" AND name LIKE ?";      $p[]="%$n%";  $t.='s'; }
    if ($co!=='') { $sql.=" AND country LIKE ?";   $p[]="%$co%"; $t.='s'; }
    if ($d!=='')  { $sql.=" AND degree_level=?";   $p[]=$d;      $t.='s'; }
    $sql.=" ORDER BY created_at DESC";
    $s=$c->prepare($sql); if ($t) $s->bind_param($t,...$p);
    $s->execute(); $r=$s->get_result()->fetch_all(MYSQLI_ASSOC);
    $s->close(); $c->close(); return $r;
}
function getMatchingScholarships($uid) {
    $c=getDBConnection();
    $s=$c->prepare("SELECT MAX(percentage) AS mx, GROUP_CONCAT(DISTINCT degree_level) AS lv FROM student_profiles WHERE user_id=?");
    $s->bind_param('i',$uid); $s->execute(); $d=$s->get_result()->fetch_assoc(); $s->close();
    if (!$d['mx']) { $c->close(); return []; }
    $sql="SELECT * FROM scholarships WHERE min_percentage <= ?"; $p=[(float)$d['mx']]; $t='d';
    if (!empty($d['lv'])) {
        $lv=explode(',',$d['lv']); $ph=implode(',',array_fill(0,count($lv),'?'));
        $sql.=" AND (degree_level IN ($ph) OR degree_level='Any')";
        foreach ($lv as $l) { $p[]=$l; $t.='s'; }
    }
    $sql.=" ORDER BY min_percentage DESC";
    $s=$c->prepare($sql); $s->bind_param($t,...$p); $s->execute();
    $r=$s->get_result()->fetch_all(MYSQLI_ASSOC); $s->close(); $c->close(); return $r;
}
function getScholarshipById($id) {
    $c=getDBConnection(); $s=$c->prepare("SELECT * FROM scholarships WHERE id=?");
    $s->bind_param('i',$id); $s->execute(); $r=$s->get_result()->fetch_assoc();
    $s->close(); $c->close(); return $r;
}
function getMyApplications($uid) {
    $c=getDBConnection();
    $s=$c->prepare("SELECT a.*,s.name AS sname,s.institute,s.country FROM applications a JOIN scholarships s ON s.id=a.scholarship_id WHERE a.user_id=? ORDER BY a.applied_at DESC");
    $s->bind_param('i',$uid); $s->execute(); $r=$s->get_result()->fetch_all(MYSQLI_ASSOC);
    $s->close(); $c->close(); return $r;
}
function getAllUsers() {
    $c=getDBConnection(); $r=$c->query("SELECT id,name,email,cnic,user_type,created_at FROM users ORDER BY created_at DESC")->fetch_all(MYSQLI_ASSOC);
    $c->close(); return $r;
}
function hasApplied($uid,$sid) {
    $c=getDBConnection(); $s=$c->prepare("SELECT id FROM applications WHERE user_id=? AND scholarship_id=?");
    $s->bind_param('ii',$uid,$sid); $s->execute(); $r=$s->get_result()->num_rows>0;
    $s->close(); $c->close(); return $r;
}
function getProfileCompletion($uid) {
    $p=getUserProfiles($uid); $lv=array_column($p,'degree_level');
    $exp=['Matric','Intermediate','Bachelor']; $done=count(array_intersect($exp,$lv));
    return (int)(($done/count($exp))*100);
}
function getAdminStats() {
    $conn=getDBConnection();
    $stats=[
        'users'=>(int)$conn->query("SELECT COUNT(*) c FROM users")->fetch_assoc()['c'],
        'students'=>(int)$conn->query("SELECT COUNT(*) c FROM users WHERE user_type='student'")->fetch_assoc()['c'],
        'admins'=>(int)$conn->query("SELECT COUNT(*) c FROM users WHERE user_type='admin'")->fetch_assoc()['c'],
        'scholarships'=>(int)$conn->query("SELECT COUNT(*) c FROM scholarships")->fetch_assoc()['c'],
        'applications'=>(int)$conn->query("SELECT COUNT(*) c FROM applications")->fetch_assoc()['c'],
        'pending'=>(int)$conn->query("SELECT COUNT(*) c FROM applications WHERE status='pending'")->fetch_assoc()['c'],
        'approved'=>(int)$conn->query("SELECT COUNT(*) c FROM applications WHERE status='approved'")->fetch_assoc()['c'],
        'rejected'=>(int)$conn->query("SELECT COUNT(*) c FROM applications WHERE status='rejected'")->fetch_assoc()['c'],
    ];
    $conn->close(); return $stats;
}
function getAllApplications() {
    $conn=getDBConnection();
    $sql="SELECT a.*,u.name AS user_name,u.email AS user_email,u.cnic,s.name AS scholarship_name,s.institute,s.country,s.degree_level FROM applications a JOIN users u ON u.id=a.user_id JOIN scholarships s ON s.id=a.scholarship_id ORDER BY CASE a.status WHEN 'pending' THEN 0 WHEN 'approved' THEN 1 ELSE 2 END, a.applied_at DESC";
    $res=$conn->query($sql)->fetch_all(MYSQLI_ASSOC); $conn->close(); return $res;
}
?>
<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Scholarship Portal — Find Your Dream Scholarship</title>
<style>
:root{
    --primary:#6366f1; --primary-dark:#4f46e5; --primary-light:#818cf8;
    --success:#10b981; --danger:#ef4444; --warning:#f59e0b; --info:#06b6d4;
    --bg:#f8fafc; --surface:#fff; --surface-2:#f1f5f9;
    --text:#0f172a; --text-muted:#64748b; --border:#e2e8f0;
    --shadow:0 4px 20px rgba(0,0,0,.06); --shadow-lg:0 10px 40px rgba(0,0,0,.12);
    --gradient:linear-gradient(135deg,#6366f1 0%,#8b5cf6 50%,#ec4899 100%);
    --gradient-dark:linear-gradient(135deg,#1e1b4b 0%,#312e81 50%,#4c1d95 100%);
    --gradient-hero:linear-gradient(135deg,#667eea 0%,#764ba2 50%,#f093fb 100%);
    --radius:14px; --transition:all .3s cubic-bezier(.4,0,.2,1);
}
[data-theme="dark"]{
    --bg:#0f172a; --surface:#1e293b; --surface-2:#334155;
    --text:#f1f5f9; --text-muted:#94a3b8; --border:#334155;
    --shadow:0 4px 20px rgba(0,0,0,.4); --shadow-lg:0 10px 40px rgba(0,0,0,.6);
}
*{margin:0;padding:0;box-sizing:border-box;font-family:'Segoe UI',system-ui,-apple-system,sans-serif}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--text);line-height:1.6;transition:background .4s,color .4s;min-height:100vh;overflow-x:hidden}
a{color:var(--primary);text-decoration:none;transition:var(--transition)}

/* ========== ANIMATIONS ========== */
@keyframes fadeIn{from{opacity:0}to{opacity:1}}
@keyframes fadeInUp{from{opacity:0;transform:translateY(30px)}to{opacity:1;transform:translateY(0)}}
@keyframes slideInLeft{from{opacity:0;transform:translateX(-40px)}to{opacity:1;transform:translateX(0)}}
@keyframes bounceIn{0%{opacity:0;transform:scale(.3)}50%{opacity:1;transform:scale(1.05)}70%{transform:scale(.95)}100%{transform:scale(1)}}
@keyframes pulse{0%,100%{transform:scale(1)}50%{transform:scale(1.05)}}
@keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-15px)}}
@keyframes float-slow{0%,100%{transform:translate(0,0) rotate(0)}33%{transform:translate(20px,-20px) rotate(5deg)}66%{transform:translate(-15px,15px) rotate(-3deg)}}
@keyframes slideDownToast{from{opacity:0;transform:translate(-50%,-100px)}to{opacity:1;transform:translate(-50%,0)}}
@keyframes progressFill{from{width:0}}
@keyframes gradientShift{0%,100%{background-position:0% 50%}50%{background-position:100% 50%}}
@keyframes spinSlow{from{transform:rotate(0)}to{transform:rotate(360deg)}}
@keyframes shimmer{0%{background-position:-1000px 0}100%{background-position:1000px 0}}
@keyframes rippleAnim{to{transform:scale(2);opacity:0}}
@keyframes blob{
    0%,100%{border-radius:60% 40% 30% 70%/60% 30% 70% 40%}
    50%{border-radius:30% 60% 70% 40%/50% 60% 30% 60%}
}

/* ========== HEADER ========== */
header{
    background:var(--gradient-dark);background-size:200% 200%;
    animation:gradientShift 15s ease infinite;
    color:#fff;padding:16px 0;position:sticky;top:0;z-index:100;
    box-shadow:var(--shadow);backdrop-filter:blur(10px);
    border-bottom:1px solid rgba(255,255,255,.1);
}
.header-content{max-width:1200px;margin:0 auto;padding:0 20px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px}
.logo{font-size:22px;font-weight:800;display:flex;align-items:center;gap:10px;letter-spacing:-.5px;animation:slideInLeft .6s ease;color:#fff}
.logo svg{animation:float 3s ease-in-out infinite}
nav ul{display:flex;list-style:none;gap:4px;flex-wrap:wrap;align-items:center}
nav a{color:rgba(255,255,255,.85);padding:8px 14px;border-radius:10px;font-size:14px;font-weight:500;transition:var(--transition);position:relative}
nav a:hover,nav a.active{background:rgba(255,255,255,.15);color:#fff;transform:translateY(-2px)}
.theme-toggle{background:rgba(255,255,255,.15);border:none;width:40px;height:40px;border-radius:50%;cursor:pointer;font-size:20px;display:flex;align-items:center;justify-content:center;transition:var(--transition)}
.theme-toggle:hover{background:rgba(255,255,255,.25);transform:rotate(180deg) scale(1.1)}

/* User avatar in nav */
.user-chip{display:flex;align-items:center;gap:8px;padding:4px 12px 4px 4px;background:rgba(255,255,255,.15);border-radius:99px}
.avatar{width:32px;height:32px;border-radius:50%;background:var(--gradient);color:#fff;font-weight:700;display:flex;align-items:center;justify-content:center;font-size:12px;border:2px solid rgba(255,255,255,.4)}

/* ========== HERO SECTION ========== */
.hero{
    position:relative;overflow:hidden;padding:80px 20px 100px;
    background:var(--gradient-hero);background-size:200% 200%;
    animation:gradientShift 15s ease infinite;color:#fff;
}
.hero::before,.hero::after{content:'';position:absolute;border-radius:50%;background:rgba(255,255,255,.1);animation:float-slow 8s ease-in-out infinite}
.hero::before{width:400px;height:400px;top:-150px;right:-100px}
.hero::after{width:300px;height:300px;bottom:-100px;left:-80px;animation-delay:-4s}
.hero-inner{max-width:1200px;margin:0 auto;display:grid;grid-template-columns:1fr 1fr;gap:60px;align-items:center;position:relative;z-index:2}
.hero-text h1{font-size:52px;font-weight:900;line-height:1.1;margin-bottom:20px;letter-spacing:-1.5px;color:#fff;animation:fadeInUp .8s ease}
.hero-text p{font-size:18px;opacity:.95;margin-bottom:32px;animation:fadeInUp .8s ease .1s both}
.hero-badges{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:32px;animation:fadeInUp .8s ease .2s both}
.hero-badge{background:rgba(255,255,255,.2);backdrop-filter:blur(10px);padding:8px 18px;border-radius:99px;font-size:14px;font-weight:600;display:flex;align-items:center;gap:6px}
.hero-cta{display:flex;gap:14px;flex-wrap:wrap;animation:fadeInUp .8s ease .3s both}
.hero-cta .btn{background:#fff;color:var(--primary);box-shadow:0 10px 30px rgba(0,0,0,.2)}
.hero-cta .btn:hover{background:#f0f0f0;transform:translateY(-3px);box-shadow:0 15px 40px rgba(0,0,0,.3)}
.hero-cta .btn-outline{background:transparent;border:2px solid rgba(255,255,255,.5);color:#fff}
.hero-cta .btn-outline:hover{background:rgba(255,255,255,.15);border-color:#fff}
.hero-illustration{position:relative;animation:fadeInUp .8s ease .2s both}
.hero-illustration svg{width:100%;max-width:500px;filter:drop-shadow(0 20px 60px rgba(0,0,0,.25))}
.hero-float{position:absolute;background:rgba(255,255,255,.95);color:var(--primary);padding:12px 18px;border-radius:14px;font-weight:700;font-size:14px;box-shadow:0 10px 30px rgba(0,0,0,.15);display:flex;align-items:center;gap:8px;animation:float 4s ease-in-out infinite}
.hero-float.f1{top:10%;left:-20px;animation-delay:0s}
.hero-float.f2{bottom:20%;right:-10px;animation-delay:-2s}

/* ========== FEATURE CARDS ========== */
.features{max-width:1200px;margin:-60px auto 40px;padding:0 20px;position:relative;z-index:10}
.features-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:20px}
.feature-card{
    background:var(--surface);padding:28px 24px;border-radius:var(--radius);
    box-shadow:var(--shadow-lg);border:1px solid var(--border);
    transition:var(--transition);text-align:center;animation:fadeInUp .6s ease both;
}
.feature-card:hover{transform:translateY(-8px);border-color:var(--primary)}
.feature-icon{
    width:64px;height:64px;margin:0 auto 16px;border-radius:18px;
    background:var(--gradient);display:flex;align-items:center;justify-content:center;
    box-shadow:0 10px 25px rgba(99,102,241,.35);
}
.feature-icon svg{width:32px;height:32px;fill:#fff}
.feature-card h3{font-size:18px;margin-bottom:8px;color:var(--text)}
.feature-card p{color:var(--text-muted);font-size:14px}

/* ========== LAYOUT ========== */
.container{max-width:1200px;margin:30px auto;padding:0 20px;animation:fadeIn .5s ease}
.section{background:var(--surface);border-radius:var(--radius);padding:30px;margin-bottom:24px;box-shadow:var(--shadow);border:1px solid var(--border);transition:var(--transition);animation:fadeInUp .6s ease both}
.section:hover{box-shadow:var(--shadow-lg)}
.section-header{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;margin-bottom:20px}
h1,h2,h3{color:var(--text);margin-bottom:16px;font-weight:700;letter-spacing:-.4px}
h1{font-size:30px;background:var(--gradient);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
h2{font-size:22px} h3{font-size:18px}

/* ========== FORMS ========== */
.form-group{margin-bottom:18px}
label{display:block;margin-bottom:6px;font-weight:600;font-size:14px;color:var(--text)}
input,select,textarea{width:100%;padding:12px 16px;border:2px solid var(--border);border-radius:10px;font-size:15px;background:var(--surface);color:var(--text);transition:var(--transition);font-family:inherit}
input:focus,select:focus,textarea:focus{outline:none;border-color:var(--primary);box-shadow:0 0 0 4px rgba(99,102,241,.15);transform:translateY(-2px)}

/* ========== BUTTONS ========== */
button,.btn{
    background:var(--gradient);background-size:200% 200%;color:#fff;border:none;
    padding:12px 24px;border-radius:10px;cursor:pointer;font-size:15px;font-weight:600;
    transition:var(--transition);display:inline-flex;align-items:center;gap:8px;
    text-decoration:none;position:relative;overflow:hidden;letter-spacing:.2px;
}
button:hover,.btn:hover{background-position:100% 50%;transform:translateY(-2px);box-shadow:0 10px 25px rgba(99,102,241,.4)}
button:active,.btn:active{transform:translateY(0) scale(.98)}
.btn-sm{padding:7px 14px;font-size:13px;border-radius:8px}
.btn-danger{background:linear-gradient(135deg,#ef4444,#dc2626)} .btn-danger:hover{box-shadow:0 10px 25px rgba(239,68,68,.4)}
.btn-success{background:linear-gradient(135deg,#10b981,#059669)} .btn-success:hover{box-shadow:0 10px 25px rgba(16,185,129,.4)}
.btn-secondary{background:linear-gradient(135deg,#64748b,#475569)} .btn-secondary:hover{box-shadow:0 10px 25px rgba(100,116,139,.4)}
.btn-warning{background:linear-gradient(135deg,#f59e0b,#d97706)}

/* ========== TOASTS ========== */
.toast-container{position:fixed;top:90px;left:50%;transform:translateX(-50%);z-index:9999;display:flex;flex-direction:column;gap:12px;pointer-events:none}
.toast{min-width:320px;max-width:500px;padding:16px 22px;border-radius:12px;font-weight:600;display:flex;align-items:center;gap:12px;pointer-events:auto;animation:slideDownToast .5s cubic-bezier(.34,1.56,.64,1) both;box-shadow:var(--shadow-lg);position:relative;overflow:hidden}
.toast::after{content:'';position:absolute;bottom:0;left:0;height:3px;background:rgba(255,255,255,.5);animation:progressFill 4s linear forwards}
.toast.success{background:linear-gradient(135deg,rgba(16,185,129,.97),rgba(5,150,105,.97));color:#fff}
.toast.error{background:linear-gradient(135deg,rgba(239,68,68,.97),rgba(220,38,38,.97));color:#fff}
.toast.warning{background:linear-gradient(135deg,rgba(245,158,11,.97),rgba(217,119,6,.97));color:#fff}
.toast-icon{font-size:22px;animation:bounceIn .6s ease}
.toast-close{background:none;border:none;color:#fff;font-size:20px;cursor:pointer;margin-left:auto;padding:0 8px;opacity:.8;transition:var(--transition);width:auto;height:auto}
.toast-close:hover{opacity:1;transform:rotate(90deg)}

/* ========== TABLES ========== */
table{width:100%;border-collapse:collapse;margin-top:16px;font-size:14px;border-radius:12px;overflow:hidden;animation:fadeInUp .7s ease}
th,td{padding:14px;text-align:left;border-bottom:1px solid var(--border)}
th{background:var(--surface-2);font-weight:700;font-size:12px;text-transform:uppercase;letter-spacing:.8px;color:var(--text-muted)}
tr{transition:var(--transition)} tr:hover td{background:var(--surface-2)}

/* ========== SCHOLARSHIP CARDS WITH IMAGES ========== */
.scholarship-card{
    border:1.5px solid var(--border);border-radius:var(--radius);margin-bottom:20px;
    background:var(--surface);transition:var(--transition);position:relative;
    overflow:hidden;animation:fadeInUp .6s ease both;display:grid;grid-template-columns:200px 1fr;
}
.scholarship-card:hover{border-color:var(--primary);box-shadow:0 15px 40px rgba(99,102,241,.18);transform:translateY(-4px)}
.scholarship-img{
    background:var(--gradient);display:flex;align-items:center;justify-content:center;
    position:relative;overflow:hidden;padding:20px;
}
.scholarship-img::before{content:'';position:absolute;inset:0;background:radial-gradient(circle at 30% 30%,rgba(255,255,255,.3),transparent 60%)}
.scholarship-img svg{width:90px;height:90px;fill:#fff;opacity:.95;position:relative;z-index:2;filter:drop-shadow(0 5px 15px rgba(0,0,0,.2))}
.scholarship-flag{position:absolute;top:12px;left:12px;font-size:32px;z-index:3;filter:drop-shadow(0 3px 8px rgba(0,0,0,.3))}
.scholarship-body{padding:24px}
.scholarship-body h3{color:var(--primary);margin-bottom:12px;display:flex;align-items:center;gap:8px;font-size:19px}
.scholarship-body p{margin-bottom:8px;font-size:14px;color:var(--text-muted)}
.scholarship-body strong{color:var(--text)}
.scholarship-meta{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}
@media(max-width:700px){.scholarship-card{grid-template-columns:1fr}.scholarship-img{height:120px}}

/* ========== GRID / STATS ========== */
.grid{display:grid;gap:20px}
.grid-2{grid-template-columns:repeat(auto-fit,minmax(280px,1fr))}
.grid-3{grid-template-columns:repeat(auto-fit,minmax(220px,1fr))}
.stat{background:var(--surface);padding:24px;border-radius:var(--radius);box-shadow:var(--shadow);border:1px solid var(--border);border-left:4px solid var(--primary);position:relative;overflow:hidden;transition:var(--transition);animation:fadeInUp .6s ease both}
.stat:hover{transform:translateY(-6px);box-shadow:var(--shadow-lg)}
.stat-icon{position:absolute;top:20px;right:20px;width:44px;height:44px;border-radius:12px;background:var(--surface-2);display:flex;align-items:center;justify-content:center;opacity:.8}
.stat-icon svg{width:22px;height:22px;fill:var(--primary)}
.stat h3{font-size:34px;background:var(--gradient);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;margin-bottom:4px;font-weight:800;line-height:1}
.stat p{color:var(--text-muted);font-size:14px;font-weight:600}

/* ========== PROGRESS BAR ========== */
.progress{background:var(--surface-2);height:12px;border-radius:99px;overflow:hidden;margin-top:10px;position:relative}
.progress-bar{height:100%;background:var(--gradient);background-size:200% 200%;border-radius:99px;transition:width 1s cubic-bezier(.4,0,.2,1);animation:gradientShift 3s ease infinite,progressFill 1.5s ease both;box-shadow:0 0 15px rgba(99,102,241,.5)}

/* ========== MODAL ========== */
.modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,.65);backdrop-filter:blur(8px);z-index:1000;align-items:center;justify-content:center;padding:20px;animation:fadeIn .3s ease}
.modal.active{display:flex}
.modal-content{background:var(--surface);border-radius:18px;padding:32px;max-width:600px;width:100%;max-height:90vh;overflow-y:auto;animation:bounceIn .5s cubic-bezier(.34,1.56,.64,1);box-shadow:var(--shadow-lg);border:1px solid var(--border);position:relative}
.modal-content::before{content:'';position:absolute;top:0;left:0;right:0;height:5px;background:var(--gradient);border-radius:18px 18px 0 0}
.modal-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:22px}
.modal-close{background:var(--surface-2);border:none;width:34px;height:34px;border-radius:50%;font-size:22px;color:var(--text-muted);cursor:pointer;display:flex;align-items:center;justify-content:center;transition:var(--transition);padding:0}
.modal-close:hover{background:var(--danger);color:#fff;transform:rotate(90deg)}

/* ========== BADGES ========== */
.badge{display:inline-flex;align-items:center;gap:4px;padding:4px 12px;border-radius:99px;font-size:12px;font-weight:700;letter-spacing:.3px;transition:var(--transition)}
.badge:hover{transform:scale(1.08)}
.badge-success{background:rgba(16,185,129,.15);color:#10b981;border:1px solid rgba(16,185,129,.3)}
.badge-warning{background:rgba(245,158,11,.15);color:#f59e0b;border:1px solid rgba(245,158,11,.3)}
.badge-danger{background:rgba(239,68,68,.15);color:#ef4444;border:1px solid rgba(239,68,68,.3)}
.badge-info{background:rgba(6,182,212,.15);color:#06b6d4;border:1px solid rgba(6,182,212,.3)}

/* ========== TABS ========== */
.tabs{display:flex;gap:6px;border-bottom:2px solid var(--border);margin-bottom:24px;flex-wrap:wrap}
.tabs a{padding:12px 22px;font-weight:600;color:var(--text-muted);border-bottom:3px solid transparent;margin-bottom:-2px;transition:var(--transition);border-radius:8px 8px 0 0}
.tabs a.active,.tabs a:hover{color:var(--primary);border-bottom-color:var(--primary);background:rgba(99,102,241,.06)}

/* ========== EMPTY STATE ========== */
.empty-state{text-align:center;padding:60px 20px;color:var(--text-muted)}
.empty-state svg{width:140px;height:140px;margin-bottom:20px;opacity:.6;animation:float 4s ease-in-out infinite}
.empty-state h3{color:var(--text);margin-bottom:8px}

/* ========== AUTH PAGES ========== */
.auth-wrap{max-width:1000px;margin:40px auto;padding:0 20px;display:grid;grid-template-columns:1fr 1fr;gap:0;border-radius:20px;overflow:hidden;box-shadow:var(--shadow-lg);background:var(--surface);border:1px solid var(--border);animation:fadeInUp .6s ease}
.auth-visual{background:var(--gradient-hero);background-size:200% 200%;animation:gradientShift 15s ease infinite;padding:50px 40px;color:#fff;display:flex;flex-direction:column;justify-content:center;position:relative;overflow:hidden}
.auth-visual::before{content:'';position:absolute;width:300px;height:300px;border-radius:50%;background:rgba(255,255,255,.1);top:-100px;right:-80px;animation:float-slow 8s ease-in-out infinite}
.auth-visual svg{width:100%;max-width:260px;margin:0 auto;position:relative;z-index:2;filter:drop-shadow(0 10px 30px rgba(0,0,0,.2))}
.auth-visual h2{color:#fff;margin-top:24px;text-align:center;position:relative;z-index:2}
.auth-visual p{opacity:.9;text-align:center;position:relative;z-index:2}
.auth-form{padding:50px 40px}
@media(max-width:800px){.auth-wrap{grid-template-columns:1fr}.auth-visual{display:none}}

/* ========== SEARCH FORM ========== */
.search-form{display:grid;grid-template-columns:1fr 1fr 1fr auto;gap:16px;align-items:end}

/* ========== FOOTER ========== */
footer{background:var(--surface);border-top:1px solid var(--border);padding:40px 20px 24px;margin-top:60px}
.footer-inner{max-width:1200px;margin:0 auto;text-align:center}
.footer-inner p{color:var(--text-muted);font-size:14px}
.footer-links{display:flex;justify-content:center;gap:24px;margin-bottom:16px;flex-wrap:wrap}
.footer-links a{color:var(--text-muted);font-size:14px}
.footer-links a:hover{color:var(--primary)}

/* ========== RESPONSIVE ========== */
@media(max-width:900px){
    .hero-inner{grid-template-columns:1fr;text-align:center}
    .hero-text h1{font-size:38px}
    .hero-illustration{order:-1}
    .hero-cta{justify-content:center}
    .hero-badges{justify-content:center}
}
@media(max-width:768px){
    .search-form{grid-template-columns:1fr}
    h1{font-size:24px}
    .section{padding:20px}
    nav a{padding:6px 10px;font-size:13px}
    .header-content{flex-direction:column;align-items:flex-start}
    .toast{min-width:280px}
    .toast-container{top:20px;width:calc(100% - 40px)}
    table{font-size:12px}
    th,td{padding:10px 6px}
    .auth-form{padding:30px 20px}
}

::-webkit-scrollbar{width:10px;height:10px}
::-webkit-scrollbar-track{background:var(--surface-2)}
::-webkit-scrollbar-thumb{background:var(--gradient);border-radius:10px}

.fab{position:fixed;bottom:30px;right:30px;width:56px;height:56px;border-radius:50%;background:var(--gradient);color:#fff;border:none;font-size:24px;cursor:pointer;box-shadow:0 10px 30px rgba(99,102,241,.5);z-index:500;display:flex;align-items:center;justify-content:center;transition:var(--transition);animation:pulse 2s ease infinite}
.fab:hover{transform:scale(1.1) rotate(90deg)}
</style>
</head>
<body>

<!-- ==================== SVG ICON LIBRARY (hidden) ==================== -->
<svg style="display:none" xmlns="http://www.w3.org/2000/svg">
    <symbol id="icon-graduation" viewBox="0 0 24 24"><path d="M12 3L1 9l11 6 9-4.91V17h2V9L12 3zM5 13.18v4L12 21l7-3.82v-4L12 17l-7-3.82z"/></symbol>
    <symbol id="icon-search" viewBox="0 0 24 24"><path d="M15.5 14h-.79l-.28-.27A6.471 6.471 0 0016 9.5 6.5 6.5 0 109.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/></symbol>
    <symbol id="icon-user" viewBox="0 0 24 24"><path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/></symbol>
    <symbol id="icon-shield" viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/></symbol>
    <symbol id="icon-book" viewBox="0 0 24 24"><path d="M18 2H6c-1.1 0-2 .9-2 2v16c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zM6 4h5v8l-2.5-1.5L6 12V4z"/></symbol>
    <symbol id="icon-star" viewBox="0 0 24 24"><path d="M12 17.27L18.18 21l-1.64-7.03L22 9.24l-7.19-.61L12 2 9.19 8.63 2 9.24l5.46 4.73L5.82 21z"/></symbol>
    <symbol id="icon-trophy" viewBox="0 0 24 24"><path d="M19 5h-2V3H7v2H5c-1.1 0-2 .9-2 2v1c0 2.55 1.92 4.63 4.39 4.94A5.01 5.01 0 0011 15.9V19H7v2h10v-2h-4v-3.1a5.01 5.01 0 003.61-2.96C19.08 12.63 21 10.55 21 8V7c0-1.1-.9-2-2-2zM5 8V7h2v3.82C5.84 10.4 5 9.3 5 8zm14 0c0 1.3-.84 2.4-2 2.82V7h2v1z"/></symbol>
    <symbol id="icon-globe" viewBox="0 0 24 24"><path d="M11.99 2C6.47 2 2 6.48 2 12s4.47 10 9.99 10C17.52 22 22 17.52 22 12S17.52 2 11.99 2zm6.93 6h-2.95a15.65 15.65 0 00-1.38-3.56A8.03 8.03 0 0118.92 8zM12 4.04c.83 1.2 1.48 2.53 1.91 3.96h-3.82c.43-1.43 1.08-2.76 1.91-3.96zM4.26 14C4.1 13.36 4 12.69 4 12s.1-1.36.26-2h3.38c-.08.66-.14 1.32-.14 2 0 .68.06 1.34.14 2H4.26zm.82 2h2.95c.32 1.25.78 2.45 1.38 3.56A7.987 7.987 0 015.08 16zm2.95-8H5.08a7.987 7.987 0 014.33-3.56A15.65 15.65 0 008.03 8zM12 19.96c-.83-1.2-1.48-2.53-1.91-3.96h3.82c-.43 1.43-1.08 2.76-1.91 3.96zM14.34 14H9.66c-.09-.66-.16-1.32-.16-2 0-.68.07-1.35.16-2h4.68c.09.65.16 1.32.16 2 0 .68-.07 1.34-.16 2zm.25 5.56c.6-1.11 1.06-2.31 1.38-3.56h2.95a8.03 8.03 0 01-4.33 3.56zM16.36 14c.08-.66.14-1.32.14-2 0-.68-.06-1.34-.14-2h3.38c.16.64.26 1.31.26 2s-.1 1.36-.26 2h-3.38z"/></symbol>
    <symbol id="icon-check" viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></symbol>
    <symbol id="icon-clock" viewBox="0 0 24 24"><path d="M11.99 2C6.47 2 2 6.48 2 12s4.47 10 9.99 10C17.52 22 22 17.52 22 12S17.52 2 11.99 2zM12 20c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8zm.5-13H11v6l5.25 3.15.75-1.23-4.5-2.67z"/></symbol>
    <symbol id="icon-doc" viewBox="0 0 24 24"><path d="M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"/></symbol>
    <symbol id="icon-heart" viewBox="0 0 24 24"><path d="M12 21.35l-1.45-1.32C5.4 15.36 2 12.28 2 8.5 2 5.42 4.42 3 7.5 3c1.74 0 3.41.81 4.5 2.09C13.09 3.81 14.76 3 16.5 3 19.58 3 22 5.42 22 8.5c0 3.78-3.4 6.86-8.55 11.54L12 21.35z"/></symbol>
</svg>

<header>
    <div class="header-content">
        <div class="logo">
            <svg width="32" height="32" viewBox="0 0 24 24" fill="#fff"><use href="#icon-graduation"/></svg>
            Scholarship Portal
        </div>
        <nav>
            <ul>
                <?php if (isset($_SESSION['user_id'])): ?>
                    <li><a href="?page=home" class="<?= ($_GET['page']??'home')==='home'?'active':'' ?>">🏠 Home</a></li>
                    <li><a href="?page=profile" class="<?= ($_GET['page']??'')==='profile'?'active':'' ?>">👤 Profile</a></li>
                    <li><a href="?page=scholarships" class="<?= ($_GET['page']??'')==='scholarships'?'active':'' ?>">🎓 Scholarships</a></li>
                    <li><a href="?page=applications" class="<?= ($_GET['page']??'')==='applications'?'active':'' ?>">📝 Applications</a></li>
                    <li><a href="?page=search" class="<?= ($_GET['page']??'')==='search'?'active':'' ?>">🔍 Search</a></li>
                    <?php if (($_SESSION['user_type']??'')==='admin'): ?>
                        <li><a href="?page=admin" class="<?= ($_GET['page']??'')==='admin'?'active':'' ?>">🛡️ Admin</a></li>
                    <?php endif; ?>
                <?php else: ?>
                    <li><a href="?page=home" class="<?= ($_GET['page']??'home')==='home'?'active':'' ?>">Home</a></li>
                    <li><a href="?page=register" class="<?= ($_GET['page']??'')==='register'?'active':'' ?>">Register</a></li>
                    <li><a href="?page=login" class="<?= ($_GET['page']??'')==='login'?'active':'' ?>">Login</a></li>
                <?php endif; ?>
                <li><button class="theme-toggle" onclick="toggleTheme()" title="Toggle theme" id="themeBtn">🌙</button></li>
                <?php if (isset($_SESSION['user_id'])): ?>
                    <li>
                        <div class="user-chip">
                            <div class="avatar"><?= e(initials($_SESSION['user_name'])) ?></div>
                            <span style="font-size:13px;font-weight:600"><?= e(explode(' ',$_SESSION['user_name'])[0]) ?></span>
                        </div>
                    </li>
                    <li>
                        <form method="post" style="display:inline">
                            <input type="hidden" name="action" value="logout">
                            <button class="btn btn-secondary btn-sm">Logout</button>
                        </form>
                    </li>
                <?php endif; ?>
            </ul>
        </nav>
    </div>
</header>

<div class="toast-container">
<?php if (!empty($_SESSION['message'])): ?>
    <div class="toast <?= e($_SESSION['message_type'] ?? 'success') ?>">
        <span class="toast-icon"><?= ($_SESSION['message_type']??'')==='error'?'❌':(($_SESSION['message_type']??'')==='warning'?'⚠️':'✅') ?></span>
        <span><?= $_SESSION['message'] ?></span>
        <button class="toast-close" onclick="this.parentElement.remove()">×</button>
    </div>
    <?php unset($_SESSION['message'], $_SESSION['message_type']); ?>
<?php endif; ?>
</div>

<?php
$page = $_GET['page'] ?? 'home';
$public = ['home','register','login'];
if (empty($_SESSION['user_id']) && !in_array($page,$public,true)) $page = 'login';
?>

<?php if ($page === 'home' && !isset($_SESSION['user_id'])): ?>
    <!-- ==================== HERO (Guest) ==================== -->
    <section class="hero">
        <div class="hero-inner">
            <div class="hero-text">
                <h1>Find Your Dream Scholarship 🎓</h1>
                <p>Discover hundreds of scholarships from top universities worldwide. Match with opportunities that fit your profile and apply in minutes.</p>
                <div class="hero-badges">
                    <div class="hero-badge">✓ Free forever</div>
                    <div class="hero-badge">✓ 1000+ scholarships</div>
                    <div class="hero-badge">✓ Smart matching</div>
                </div>
                <div class="hero-cta">
                    <a href="?page=register" class="btn">Get Started Free</a>
                    <a href="?page=login" class="btn btn-outline">Sign In</a>
                </div>
            </div>
            <div class="hero-illustration">
                <svg viewBox="0 0 500 500" xmlns="http://www.w3.org/2000/svg">
                    <defs>
                        <linearGradient id="g1" x1="0%" y1="0%" x2="100%" y2="100%">
                            <stop offset="0%" stop-color="#fff" stop-opacity=".9"/>
                            <stop offset="100%" stop-color="#fff" stop-opacity=".6"/>
                        </linearGradient>
                    </defs>
                    <!-- Book -->
                    <ellipse cx="250" cy="420" rx="180" ry="20" fill="rgba(0,0,0,.15)"/>
                    <path d="M100 200 Q100 180 130 180 L380 180 Q410 180 410 200 L410 380 Q410 400 380 400 L130 400 Q100 400 100 380 Z" fill="url(#g1)"/>
                    <path d="M255 180 L255 400" stroke="#4f46e5" stroke-width="2" opacity=".3"/>
                    <path d="M130 200 L245 200 L245 380 L130 380 Z" fill="rgba(255,255,255,.4)"/>
                    <path d="M265 200 L380 200 L380 380 L265 380 Z" fill="rgba(255,255,255,.4)"/>
                    <line x1="150" y1="230" x2="225" y2="230" stroke="#4f46e5" stroke-width="3" opacity=".5" stroke-linecap="round"/>
                    <line x1="150" y1="255" x2="225" y2="255" stroke="#4f46e5" stroke-width="3" opacity=".5" stroke-linecap="round"/>
                    <line x1="150" y1="280" x2="200" y2="280" stroke="#4f46e5" stroke-width="3" opacity=".5" stroke-linecap="round"/>
                    <line x1="285" y1="230" x2="360" y2="230" stroke="#ec4899" stroke-width="3" opacity=".5" stroke-linecap="round"/>
                    <line x1="285" y1="255" x2="360" y2="255" stroke="#ec4899" stroke-width="3" opacity=".5" stroke-linecap="round"/>
                    <line x1="285" y1="280" x2="335" y2="280" stroke="#ec4899" stroke-width="3" opacity=".5" stroke-linecap="round"/>
                    <!-- Graduation Cap -->
                    <path d="M250 90 L100 160 L250 230 L400 160 Z" fill="#fbbf24"/>
                    <path d="M250 90 L400 160 L250 230 Z" fill="#f59e0b"/>
                    <rect x="370" y="160" width="8" height="80" fill="#dc2626"/>
                    <circle cx="374" cy="240" r="10" fill="#dc2626"/>
                    <!-- Star sparkles -->
                    <circle cx="120" cy="120" r="4" fill="#fff" opacity=".8"/>
                    <circle cx="420" cy="100" r="3" fill="#fff" opacity=".6"/>
                    <circle cx="80" cy="300" r="3" fill="#fff" opacity=".7"/>
                    <circle cx="440" cy="300" r="4" fill="#fff" opacity=".5"/>
                </svg>
                <div class="hero-float f1">🎓 1000+ Programs</div>
                <div class="hero-float f2">🌍 50+ Countries</div>
            </div>
        </div>
    </section>

    <!-- Feature Cards -->
    <section class="features">
        <div class="features-grid">
            <div class="feature-card">
                <div class="feature-icon"><svg><use href="#icon-search"/></svg></div>
                <h3>Smart Search</h3>
                <p>Filter scholarships by country, degree, and more.</p>
            </div>
            <div class="feature-card">
                <div class="feature-icon" style="background:linear-gradient(135deg,#10b981,#059669)"><svg><use href="#icon-book"/></svg></div>
                <h3>Build Profile</h3>
                <p>Add your education history from Matric to PhD.</p>
            </div>
            <div class="feature-card">
                <div class="feature-icon" style="background:linear-gradient(135deg,#f59e0b,#d97706)"><svg><use href="#icon-trophy"/></svg></div>
                <h3>Auto Matching</h3>
                <p>See scholarships that fit your academic profile.</p>
            </div>
            <div class="feature-card">
                <div class="feature-icon" style="background:linear-gradient(135deg,#ec4899,#db2777)"><svg><use href="#icon-heart"/></svg></div>
                <h3>Track Applications</h3>
                <p>Apply and monitor your applications in one place.</p>
            </div>
        </div>
    </section>
<?php endif; ?>

<div class="container">
    <?php
    switch ($page) {
        case 'register':     pageRegister();     break;
        case 'login':        pageLogin();        break;
        case 'profile':      pageProfile();      break;
        case 'scholarships': pageScholarships(); break;
        case 'applications': pageApplications(); break;
        case 'search':       pageSearch();       break;
        case 'admin':        pageAdmin();        break;
        default:             pageHome();
    }
    ?>
</div>

<footer>
    <div class="footer-inner">
        <div class="footer-links">
            <a href="?page=home">Home</a>
            <a href="?page=scholarships">Scholarships</a>
            <a href="?page=search">Search</a>
            <a href="?page=login">Login</a>
        </div>
        <p>&copy; <?= date('Y') ?> Scholarship Portal — Empowering students worldwide 🌍</p>
    </div>
</footer>

<button class="fab" onclick="window.scrollTo({top:0,behavior:'smooth'})" title="Back to top">↑</button>

<script>
function applyTheme(t){document.documentElement.setAttribute('data-theme',t);document.getElementById('themeBtn').textContent=t==='dark'?'☀️':'🌙';localStorage.setItem('theme',t)}
function toggleTheme(){applyTheme(document.documentElement.getAttribute('data-theme')==='dark'?'light':'dark')}
(function(){const s=localStorage.getItem('theme');const p=window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light';applyTheme(s||p)})();

document.querySelectorAll('.toast').forEach(t=>{setTimeout(()=>{t.style.transition='all .4s';t.style.opacity='0';t.style.transform='translate(-50%,-30px)';setTimeout(()=>t.remove(),400)},4000)});

function openModal(id){const m=document.getElementById(id);if(m){m.classList.add('active');document.body.style.overflow='hidden'}}
function closeModal(id){const m=document.getElementById(id);if(m){m.classList.remove('active');document.body.style.overflow=''}}
document.addEventListener('click',e=>{if(e.target.classList.contains('modal')){e.target.classList.remove('active');document.body.style.overflow=''}});
document.addEventListener('keydown',e=>{if(e.key==='Escape')document.querySelectorAll('.modal.active').forEach(m=>{m.classList.remove('active');document.body.style.overflow=''})});

function editProfile(d){document.getElementById('edit_profile_id').value=d.id;document.getElementById('edit_degree_level').value=d.degree_level;document.getElementById('edit_degree_name').value=d.degree_name;document.getElementById('edit_institute').value=d.institute;document.getElementById('edit_year').value=d.year;document.getElementById('edit_percentage').value=d.percentage;document.getElementById('edit_grade').value=d.grade||'';openModal('editProfileModal')}
function openResetModal(id,name){document.getElementById('reset_user_id').value=id;document.getElementById('reset_user_name').textContent=name;document.getElementById('reset_pw_field').value='';openModal('resetPasswordModal');setTimeout(()=>document.getElementById('reset_pw_field').focus(),300)}

function animateCounters(){document.querySelectorAll('[data-count]').forEach(el=>{const t=parseInt(el.getAttribute('data-count'),10);const s=el.getAttribute('data-suffix')||'';let c=0;const st=Math.max(1,Math.ceil(t/40));const timer=setInterval(()=>{c+=st;if(c>=t){c=t;clearInterval(timer)}el.textContent=c+s},25)})}
document.addEventListener('DOMContentLoaded',animateCounters);

document.addEventListener('click',function(e){const btn=e.target.closest('button, .btn');if(!btn)return;const r=btn.getBoundingClientRect();const ripple=document.createElement('span');const size=Math.max(r.width,r.height);ripple.style.cssText=`position:absolute;width:${size}px;height:${size}px;border-radius:50%;background:rgba(255,255,255,.5);transform:scale(0);animation:rippleAnim .6s ease-out;left:${e.clientX-r.left-size/2}px;top:${e.clientY-r.top-size/2}px;pointer-events:none`;btn.style.position='relative';btn.style.overflow='hidden';btn.appendChild(ripple);setTimeout(()=>ripple.remove(),600)});

document.querySelectorAll('form').forEach(f=>{f.addEventListener('submit',()=>{const b=f.querySelector('button[type="submit"], button:not([type])');if(b&&!b.disabled){b.disabled=true;b.dataset.orig=b.innerHTML;b.innerHTML='⏳ Processing...';setTimeout(()=>{b.disabled=false;b.innerHTML=b.dataset.orig},3000)}})});

const obs=new IntersectionObserver(es=>{es.forEach(e=>{if(e.isIntersecting){e.target.style.opacity='1';e.target.style.transform='translateY(0)';obs.unobserve(e.target)}})},{threshold:.1});
document.querySelectorAll('.scholarship-card, .stat, .feature-card').forEach(el=>{el.style.opacity='0';el.style.transform='translateY(20px)';el.style.transition='all .6s ease';obs.observe(el)});
</script>
</body>
</html>

<?php
// ==================== PAGE RENDERERS ====================

function pageHome() {
    $logged = isset($_SESSION['user_id']);
    ?>
    <?php if ($logged): ?>
    <div class="section">
        <h1>👋 Welcome back, <?= e($_SESSION['user_name']) ?>!</h1>
        <p style="color:var(--text-muted);font-size:16px;margin-bottom:24px">Here's your dashboard overview</p>

        <?php
        $uid = (int)$_SESSION['user_id'];
        $pct = getProfileCompletion($uid);
        $match = count(getMatchingScholarships($uid));
        $apps = count(getMyApplications($uid));
        ?>
        <div class="grid grid-3">
            <div class="stat">
                <div class="stat-icon"><svg><use href="#icon-user"/></svg></div>
                <h3 data-count="<?= $pct ?>" data-suffix="%">0%</h3>
                <p>Profile Completion</p>
                <div class="progress"><div class="progress-bar" style="width:<?= $pct ?>%"></div></div>
            </div>
            <div class="stat" style="border-left-color:var(--success)">
                <div class="stat-icon" style="background:rgba(16,185,129,.15)"><svg style="fill:var(--success)"><use href="#icon-trophy"/></svg></div>
                <h3 data-count="<?= $match ?>">0</h3>
                <p>Matching Scholarships</p>
            </div>
            <div class="stat" style="border-left-color:var(--warning)">
                <div class="stat-icon" style="background:rgba(245,158,11,.15)"><svg style="fill:var(--warning)"><use href="#icon-doc"/></svg></div>
                <h3 data-count="<?= $apps ?>">0</h3>
                <p>My Applications</p>
            </div>
        </div>

        <div style="display:flex;gap:12px;margin-top:30px;flex-wrap:wrap">
            <a href="?page=profile" class="btn">🎓 Build Profile</a>
            <a href="?page=scholarships" class="btn btn-success">✨ View Matches</a>
            <a href="?page=search" class="btn btn-secondary">🔍 Search</a>
        </div>
    </div>
    <?php endif; ?>

    <div class="section">
        <div class="section-header">
            <h2>🌟 Latest Scholarships</h2>
            <a href="?page=scholarships" class="btn btn-sm btn-secondary">View All →</a>
        </div>
        <?php $schs = array_slice(getAllScholarships(),0,3); ?>
        <?php if ($schs): foreach ($schs as $s): ?>
            <?php renderScholarshipCard($s, $_SESSION['user_id'] ?? 0, false); ?>
        <?php endforeach; else: ?>
            <div class="empty-state">
                <svg viewBox="0 0 24 24" fill="var(--text-muted)"><use href="#icon-doc"/></svg>
                <h3>No scholarships yet</h3>
                <p>Check back soon for new opportunities</p>
            </div>
        <?php endif; ?>
    </div>
    <?php
}

function pageRegister() { ?>
    <div class="auth-wrap">
        <div class="auth-visual">
            <svg viewBox="0 0 300 300" xmlns="http://www.w3.org/2000/svg">
                <circle cx="150" cy="150" r="120" fill="rgba(255,255,255,.1)" style="animation:blob 6s ease-in-out infinite"/>
                <path d="M100 130 L150 100 L200 130 L150 160 Z" fill="#fbbf24"/>
                <path d="M150 100 L200 130 L150 160 Z" fill="#f59e0b"/>
                <rect x="185" y="130" width="5" height="50" fill="#dc2626"/>
                <circle cx="187.5" cy="185" r="7" fill="#dc2626"/>
                <circle cx="90" cy="200" r="25" fill="rgba(255,255,255,.2)"/>
                <circle cx="210" cy="90" r="18" fill="rgba(255,255,255,.2)"/>
            </svg>
            <h2>Join Thousands of Students</h2>
            <p>Start your scholarship journey today</p>
        </div>
        <div class="auth-form">
            <h1>Create Account</h1>
            <p style="color:var(--text-muted);margin-bottom:24px">Fill in your details to get started</p>
            <form method="post">
                <input type="hidden" name="action" value="register">
                <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
                <div class="form-group"><label>Full Name</label><input name="name" required placeholder="John Doe"></div>
                <div class="form-group"><label>Email</label><input type="email" name="email" required placeholder="you@example.com"></div>
                <div class="form-group"><label>CNIC (00000-0000000-0)</label>
                    <input name="cnic" pattern="\d{5}-\d{7}-\d{1}" placeholder="12345-1234567-1" required></div>
                <div class="form-group"><label>Password (min 6 chars)</label>
                    <input type="password" name="password" minlength="6" required placeholder="••••••"></div>
                <button class="btn" style="width:100%;justify-content:center">Create Account →</button>
                <p style="text-align:center;margin-top:16px;color:var(--text-muted);font-size:14px">
                    Already have an account? <a href="?page=login">Sign in</a>
                </p>
            </form>
        </div>
    </div>
<?php }

function pageLogin() { ?>
    <div class="auth-wrap">
        <div class="auth-visual">
            <svg viewBox="0 0 300 300" xmlns="http://www.w3.org/2000/svg">
                <circle cx="150" cy="150" r="120" fill="rgba(255,255,255,.1)" style="animation:blob 6s ease-in-out infinite"/>
                <rect x="100" y="140" width="100" height="80" rx="10" fill="rgba(255,255,255,.3)"/>
                <path d="M120 140 V120 A30 30 0 0 1 180 120 V140" stroke="#fbbf24" stroke-width="10" fill="none" stroke-linecap="round"/>
                <circle cx="150" cy="180" r="10" fill="#fbbf24"/>
                <rect x="146" y="185" width="8" height="15" fill="#fbbf24" rx="3"/>
            </svg>
            <h2>Welcome Back!</h2>
            <p>Sign in to continue your journey</p>
        </div>
        <div class="auth-form">
            <h1>Sign In</h1>
            <p style="color:var(--text-muted);margin-bottom:24px">Enter your credentials to access your account</p>
            <form method="post">
                <input type="hidden" name="action" value="login">
                <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
                <div class="form-group"><label>Email</label><input type="email" name="email" required placeholder="you@example.com"></div>
                <div class="form-group"><label>Password</label><input type="password" name="password" required placeholder="••••••"></div>
                <button class="btn" style="width:100%;justify-content:center">Sign In →</button>
                <p style="text-align:center;margin-top:16px;color:var(--text-muted);font-size:14px">
                    Don't have an account? <a href="?page=register">Create one</a>
                </p>
                <div style="margin-top:20px;padding:12px;background:var(--surface-2);border-radius:8px;font-size:12px;color:var(--text-muted)">
                    <strong>Demo Admin:</strong> admin@scholarship.com / admin123
                </div>
            </form>
        </div>
    </div>
<?php }

function pageProfile() {
    $uid = (int)$_SESSION['user_id'];
    $profiles = getUserProfiles($uid);
    $pct = getProfileCompletion($uid);
    ?>
    <div class="section">
        <div class="section-header">
            <div>
                <h1>👤 My Education Profile</h1>
                <p style="color:var(--text-muted)">Add your academic history to find matching scholarships</p>
            </div>
        </div>
        <p style="font-weight:600">Completion: <?= $pct ?>%</p>
        <div class="progress"><div class="progress-bar" style="width:<?= $pct ?>%"></div></div>

        <h2 style="margin-top:28px">➕ Add Education Record</h2>
        <form method="post">
            <input type="hidden" name="action" value="add_profile">
            <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
            <div class="grid grid-2">
                <div class="form-group"><label>Degree Level</label>
                    <select name="degree_level" required>
                        <option value="">Select...</option>
                        <?php foreach (['Matric','Intermediate','Bachelor','Master','PhD'] as $l): ?>
                            <option><?= $l ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="form-group"><label>Degree Name</label><input name="degree_name" required placeholder="e.g., Computer Science"></div>
                <div class="form-group"><label>Institute</label><input name="institute" required placeholder="e.g., Punjab University"></div>
                <div class="form-group"><label>Year</label><input name="year" required placeholder="2023"></div>
                <div class="form-group"><label>Percentage</label><input type="number" step="0.01" min="0" max="100" name="percentage" required placeholder="85.5"></div>
                <div class="form-group"><label>Grade (optional)</label><input name="grade" placeholder="A+"></div>
            </div>
            <button class="btn">➕ Add Record</button>
        </form>
    </div>

    <div class="section">
        <h2>📚 Education History</h2>
        <?php if ($profiles): ?>
            <table>
                <thead><tr><th>Level</th><th>Degree</th><th>Institute</th><th>Year</th><th>%</th><th>Grade</th><th>Actions</th></tr></thead>
                <tbody>
                <?php foreach ($profiles as $p): ?>
                    <tr>
                        <td><span class="badge badge-info"><?= e($p['degree_level']) ?></span></td>
                        <td><?= e($p['degree_name']) ?></td>
                        <td><?= e($p['institute']) ?></td>
                        <td><?= e($p['year']) ?></td>
                        <td><strong><?= e($p['percentage']) ?>%</strong></td>
                        <td><?= e($p['grade']) ?></td>
                        <td style="display:flex;gap:6px">
                            <button class="btn btn-secondary btn-sm"
                                onclick='editProfile(<?= json_encode($p, JSON_HEX_APOS|JSON_HEX_QUOT) ?>)'>✏️ Edit</button>
                            <form method="post" style="display:inline" onsubmit="return confirm('Delete?')">
                                <input type="hidden" name="action" value="delete_profile">
                                <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
                                <input type="hidden" name="profile_id" value="<?= (int)$p['id'] ?>">
                                <button class="btn btn-danger btn-sm">🗑</button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        <?php else: ?>
            <div class="empty-state">
                <svg viewBox="0 0 24 24" fill="var(--text-muted)"><use href="#icon-book"/></svg>
                <h3>No records yet</h3>
                <p>Add your first education record above to get started</p>
            </div>
        <?php endif; ?>
    </div>

    <div class="modal" id="editProfileModal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>✏️ Edit Education Record</h3>
                <button class="modal-close" onclick="closeModal('editProfileModal')">×</button>
            </div>
            <form method="post">
                <input type="hidden" name="action" value="update_profile">
                <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
                <input type="hidden" name="profile_id" id="edit_profile_id">
                <div class="form-group"><label>Degree Level</label>
                    <select name="degree_level" id="edit_degree_level" required>
                        <?php foreach (['Matric','Intermediate','Bachelor','Master','PhD'] as $l): ?>
                            <option><?= $l ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="form-group"><label>Degree Name</label><input name="degree_name" id="edit_degree_name" required></div>
                <div class="form-group"><label>Institute</label><input name="institute" id="edit_institute" required></div>
                <div class="form-group"><label>Year</label><input name="year" id="edit_year" required></div>
                <div class="form-group"><label>Percentage</label><input type="number" step="0.01" name="percentage" id="edit_percentage" required></div>
                <div class="form-group"><label>Grade</label><input name="grade" id="edit_grade"></div>
                <button class="btn">Update</button>
                <button type="button" class="btn btn-secondary" onclick="closeModal('editProfileModal')">Cancel</button>
            </form>
        </div>
    </div>
    <?php
}

function pageScholarships() {
    $uid = (int)$_SESSION['user_id'];
    $matching = getMatchingScholarships($uid);
    $all = getAllScholarships();
    ?>
    <div class="section">
        <div class="section-header">
            <h1>🎯 Matching Your Profile</h1>
            <span class="badge badge-success"><?= count($matching) ?> matches</span>
        </div>
        <?php if ($matching): foreach ($matching as $s) renderScholarshipCard($s,$uid,true);
        else: ?>
            <div class="empty-state">
                <svg viewBox="0 0 24 24" fill="var(--text-muted)"><use href="#icon-search"/></svg>
                <h3>No matches yet</h3>
                <p>Build your profile to see personalized matches</p>
                <a href="?page=profile" class="btn" style="margin-top:16px">Build Profile</a>
            </div>
        <?php endif; ?>
    </div>

    <div class="section">
        <div class="section-header">
            <h2>📚 All Scholarships</h2>
            <span class="badge badge-info"><?= count($all) ?> total</span>
        </div>
        <?php if ($all): foreach ($all as $s) renderScholarshipCard($s,$uid,false);
        else: ?><p>No scholarships available.</p><?php endif; ?>
    </div>
    <?php
}

function renderScholarshipCard($s,$uid,$showBenefits) {
    $applied = $uid ? hasApplied($uid,(int)$s['id']) : false;
    $flag = country_flag($s['country']);
    ?>
    <div class="scholarship-card">
        <div class="scholarship-img">
            <span class="scholarship-flag"><?= $flag ?></span>
            <svg viewBox="0 0 24 24"><use href="#icon-graduation"/></svg>
        </div>
        <div class="scholarship-body">
            <h3>🎓 <?= e($s['name']) ?></h3>
            <p>🏛️ <strong>Institute:</strong> <?= e($s['institute']) ?></p>
            <p><?= $flag ?> <strong>Country:</strong> <?= e($s['country']) ?></p>
            <p>📖 <strong>Degree:</strong> <span class="badge badge-info"><?= e($s['degree_level']) ?></span></p>
            <p>📊 <strong>Min %:</strong> <?= e($s['min_percentage']) ?>%</p>
            <?php if ($showBenefits): ?>
                <p>💰 <strong>Benefits:</strong> <?= e($s['benefits']) ?></p>
                <p>📋 <strong>Requirements:</strong> <?= e($s['requirements']) ?></p>
            <?php endif; ?>
            <?php if ($s['deadline']): ?>
                <p>⏰ <strong>Deadline:</strong> <span class="badge badge-warning"><?= e($s['deadline']) ?></span></p>
            <?php endif; ?>
            <div class="scholarship-meta">
                <?php if ($applied): ?>
                    <span class="badge badge-success">✓ Applied</span>
                <?php elseif ($uid): ?>
                    <form method="post" style="display:inline">
                        <input type="hidden" name="action" value="apply">
                        <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
                        <input type="hidden" name="scholarship_id" value="<?= (int)$s['id'] ?>">
                        <button class="btn btn-sm">Apply Now →</button>
                    </form>
                <?php else: ?>
                    <a href="?page=login" class="btn btn-sm">Login to Apply</a>
                <?php endif; ?>
            </div>
        </div>
    </div>
    <?php
}

function pageApplications() {
    $apps = getMyApplications((int)$_SESSION['user_id']);
    ?>
    <div class="section">
        <h1>📝 My Applications</h1>
        <p style="color:var(--text-muted);margin-bottom:16px">Track the status of each application.</p>
        <?php if ($apps): ?>
            <table>
                <thead><tr><th>Scholarship</th><th>Institute</th><th>Country</th><th>Status</th><th>Applied</th></tr></thead>
                <tbody>
                <?php foreach ($apps as $a):
                    $cls = $a['status']==='approved'?'success':($a['status']==='rejected'?'danger':'warning');
                    $ico = $a['status']==='approved'?'✓':($a['status']==='rejected'?'✗':'⏳');
                ?>
                    <tr>
                        <td><?= e($a['sname']) ?></td>
                        <td><?= e($a['institute']) ?></td>
                        <td><?= country_flag($a['country']) ?> <?= e($a['country']) ?></td>
                        <td><span class="badge badge-<?= $cls ?>"><?= $ico ?> <?= e(ucfirst($a['status'])) ?></span></td>
                        <td><?= e($a['applied_at']) ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        <?php else: ?>
            <div class="empty-state">
                <svg viewBox="0 0 24 24" fill="var(--text-muted)"><use href="#icon-doc"/></svg>
                <h3>No applications yet</h3>
                <p>Browse scholarships and start applying</p>
                <a href="?page=scholarships" class="btn" style="margin-top:16px">Browse Scholarships</a>
            </div>
        <?php endif; ?>
    </div>
    <?php
}

function pageSearch() {
    $n = trim($_GET['search_name']??''); $co = trim($_GET['search_country']??''); $d = trim($_GET['search_degree']??'');
    $results = ($n||$co||$d) ? searchScholarships($n,$co,$d) : null;
    $uid = (int)$_SESSION['user_id'];
    ?>
    <div class="section">
        <h1>🔍 Search Scholarships</h1>
        <form method="get">
            <input type="hidden" name="page" value="search">
            <div class="search-form">
                <div class="form-group"><label>Name</label><input name="search_name" value="<?= e($n) ?>" placeholder="Scholarship name"></div>
                <div class="form-group"><label>Country</label><input name="search_country" value="<?= e($co) ?>" placeholder="Country"></div>
                <div class="form-group"><label>Degree</label>
                    <select name="search_degree">
                        <option value="">All Degrees</option>
                        <?php foreach (['Matric','Intermediate','Bachelor','Master','PhD','Any'] as $x): ?>
                            <option <?= $d===$x?'selected':'' ?>><?= $x ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="form-group"><button class="btn">🔍 Search</button></div>
            </div>
        </form>
        <?php if ($results !== null): ?>
            <h2 style="margin-top:24px">Results (<?= count($results) ?>)</h2>
            <?php if ($results): foreach ($results as $s) renderScholarshipCard($s,$uid,true);
            else: ?>
                <div class="empty-state">
                    <svg viewBox="0 0 24 24" fill="var(--text-muted)"><use href="#icon-search"/></svg>
                    <h3>No results</h3>
                    <p>Try different keywords</p>
                </div>
            <?php endif; ?>
        <?php endif; ?>
    </div>
    <?php
}

function pageAdmin() {
    if (($_SESSION['user_type'] ?? '') !== 'admin') {
        echo '<div class="section"><div class="empty-state"><svg viewBox="0 0 24 24" fill="var(--danger)"><use href="#icon-shield"/></svg><h3>Access Denied</h3><p>Admin privileges required.</p></div></div>';
        return;
    }
    $tab     = $_GET['tab'] ?? 'dashboard';
    $edit_id = (int)($_GET['edit'] ?? 0);
    $edit    = $edit_id ? getScholarshipById($edit_id) : null;
    $stats   = getAdminStats();
    ?>
    <div class="section">
        <div class="section-header">
            <div>
                <h1>🛡️ Admin Control Panel</h1>
                <p style="color:var(--text-muted)">Logged in as <strong><?= e($_SESSION['user_name']) ?></strong></p>
            </div>
        </div>

        <div class="tabs">
            <a href="?page=admin&tab=dashboard"    class="<?= $tab==='dashboard'?'active':'' ?>">📊 Dashboard</a>
            <a href="?page=admin&tab=scholarships" class="<?= $tab==='scholarships'?'active':'' ?>">🎓 Scholarships</a>
            <a href="?page=admin&tab=applications" class="<?= $tab==='applications'?'active':'' ?>">
                📝 Applications
                <?php if ($stats['pending'] > 0): ?>
                    <span class="badge badge-warning" style="margin-left:6px"><?= $stats['pending'] ?> new</span>
                <?php endif; ?>
            </a>
            <a href="?page=admin&tab=users" class="<?= $tab==='users'?'active':'' ?>">👥 Users (<?= $stats['users'] ?>)</a>
        </div>

        <?php if ($tab === 'dashboard'): ?>
            <h2>System Overview</h2>
            <div class="grid grid-3" style="margin-top:20px">
                <div class="stat"><div class="stat-icon"><svg><use href="#icon-user"/></svg></div><h3 data-count="<?= $stats['users'] ?>">0</h3><p>Total Users</p></div>
                <div class="stat" style="border-left-color:var(--info)"><div class="stat-icon" style="background:rgba(6,182,212,.15)"><svg style="fill:var(--info)"><use href="#icon-graduation"/></svg></div><h3 data-count="<?= $stats['scholarships'] ?>">0</h3><p>Scholarships</p></div>
                <div class="stat" style="border-left-color:var(--success)"><div class="stat-icon" style="background:rgba(16,185,129,.15)"><svg style="fill:var(--success)"><use href="#icon-doc"/></svg></div><h3 data-count="<?= $stats['applications'] ?>">0</h3><p>Applications</p></div>
                <div class="stat" style="border-left-color:var(--warning)"><h3 data-count="<?= $stats['pending'] ?>">0</h3><p>⏳ Pending Review</p></div>
                <div class="stat" style="border-left-color:var(--success)"><h3 data-count="<?= $stats['approved'] ?>">0</h3><p>✓ Approved</p></div>
                <div class="stat" style="border-left-color:var(--danger)"><h3 data-count="<?= $stats['rejected'] ?>">0</h3><p>✗ Rejected</p></div>
            </div>

            <div class="grid grid-2" style="margin-top:30px">
                <div>
                    <h3>👥 User Breakdown</h3>
                    <p>Students: <strong><?= $stats['students'] ?></strong></p>
                    <p>Admins: <strong><?= $stats['admins'] ?></strong></p>
                </div>
                <div>
                    <h3>⚡ Quick Actions</h3>
                    <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:10px">
                        <a href="?page=admin&tab=scholarships" class="btn btn-sm">➕ Add Scholarship</a>
                        <a href="?page=admin&tab=applications" class="btn btn-warning btn-sm">📝 Review Applications</a>
                        <a href="?page=admin&tab=users" class="btn btn-secondary btn-sm">👥 Manage Users</a>
                    </div>
                </div>
            </div>

        <?php elseif ($tab === 'applications'): ?>
            <h2>📝 Application Verification</h2>
            <p style="color:var(--text-muted);margin-bottom:16px">Approve or reject student applications.</p>
            <?php $apps = getAllApplications(); ?>
            <?php if ($apps): ?>
                <table>
                    <thead><tr><th>Student</th><th>Email</th><th>Scholarship</th><th>Status</th><th>Applied</th><th>Actions</th></tr></thead>
                    <tbody>
                    <?php foreach ($apps as $a): ?>
                        <tr>
                            <td>
                                <div style="display:flex;align-items:center;gap:8px">
                                    <div class="avatar" style="background:var(--gradient)"><?= e(initials($a['user_name'])) ?></div>
                                    <?= e($a['user_name']) ?>
                                </div>
                            </td>
                            <td><?= e($a['user_email']) ?></td>
                            <td><?= e($a['scholarship_name']) ?></td>
                            <td><span class="badge badge-<?= $a['status']==='approved'?'success':($a['status']==='rejected'?'danger':'warning') ?>"><?= e(ucfirst($a['status'])) ?></span></td>
                            <td style="font-size:12px"><?= e($a['applied_at']) ?></td>
                            <td style="display:flex;gap:6px;flex-wrap:wrap">
                                <?php if ($a['status'] !== 'approved'): ?>
                                    <form method="post" style="display:inline">
                                        <input type="hidden" name="action" value="update_application">
                                        <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
                                        <input type="hidden" name="application_id" value="<?= (int)$a['id'] ?>">
                                        <input type="hidden" name="status" value="approved">
                                        <button class="btn btn-success btn-sm">✓</button>
                                    </form>
                                <?php endif; ?>
                                <?php if ($a['status'] !== 'rejected'): ?>
                                    <form method="post" style="display:inline">
                                        <input type="hidden" name="action" value="update_application">
                                        <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
                                        <input type="hidden" name="application_id" value="<?= (int)$a['id'] ?>">
                                        <input type="hidden" name="status" value="rejected">
                                        <button class="btn btn-danger btn-sm">✗</button>
                                    </form>
                                <?php endif; ?>
                                <?php if ($a['status'] !== 'pending'): ?>
                                    <form method="post" style="display:inline">
                                        <input type="hidden" name="action" value="update_application">
                                        <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
                                        <input type="hidden" name="application_id" value="<?= (int)$a['id'] ?>">
                                        <input type="hidden" name="status" value="pending">
                                        <button class="btn btn-secondary btn-sm">↺</button>
                                    </form>
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            <?php else: ?>
                <div class="empty-state">
                    <svg viewBox="0 0 24 24" fill="var(--text-muted)"><use href="#icon-doc"/></svg>
                    <h3>No applications yet</h3>
                    <p>Students haven't applied to any scholarships</p>
                </div>
            <?php endif; ?>

        <?php elseif ($tab === 'users'): ?>
            <h2>👥 User Management</h2>
            <p style="color:var(--text-muted);margin-bottom:16px">Reset passwords, change roles, or delete accounts.</p>
            <table>
                <thead><tr><th>User</th><th>Email</th><th>CNIC</th><th>Role</th><th>Actions</th></tr></thead>
                <tbody>
                <?php foreach (getAllUsers() as $u):
                    $isSelf = (int)$u['id'] === (int)$_SESSION['user_id'];
                ?>
                    <tr>
                        <td>
                            <div style="display:flex;align-items:center;gap:10px">
                                <div class="avatar" style="background:var(--gradient);width:36px;height:36px;font-size:13px"><?= e(initials($u['name'])) ?></div>
                                <div>
                                    <div style="font-weight:600"><?= e($u['name']) ?><?= $isSelf ? ' <span class="badge badge-info">You</span>' : '' ?></div>
                                    <div style="font-size:12px;color:var(--text-muted)"><?= e($u['created_at']) ?></div>
                                </div>
                            </div>
                        </td>
                        <td><?= e($u['email']) ?></td>
                        <td style="font-family:monospace;font-size:12px"><?= e($u['cnic']) ?></td>
                        <td><span class="badge badge-<?= $u['user_type']==='admin'?'danger':'info' ?>"><?= e(ucfirst($u['user_type'])) ?></span></td>
                        <td style="display:flex;gap:6px;flex-wrap:wrap">
                            <button class="btn btn-warning btn-sm" onclick="openResetModal(<?= (int)$u['id'] ?>, '<?= e(addslashes($u['name'])) ?>')" title="Reset Password">🔑</button>
                            <?php if (!$isSelf): ?>
                                <form method="post" style="display:inline" onsubmit="return confirm('Change role?')">
                                    <input type="hidden" name="action" value="toggle_role">
                                    <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
                                    <input type="hidden" name="user_id" value="<?= (int)$u['id'] ?>">
                                    <button class="btn btn-secondary btn-sm" title="Toggle Role"><?= $u['user_type']==='admin' ? '⬇' : '⬆' ?></button>
                                </form>
                                <form method="post" style="display:inline" onsubmit="return confirm('Delete user?')">
                                    <input type="hidden" name="action" value="delete_user">
                                    <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
                                    <input type="hidden" name="user_id" value="<?= (int)$u['id'] ?>">
                                    <button class="btn btn-danger btn-sm" title="Delete">🗑</button>
                                </form>
                            <?php endif; ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>

            <div class="modal" id="resetPasswordModal">
                <div class="modal-content" style="max-width:420px">
                    <div class="modal-header">
                        <h3>🔑 Reset Password</h3>
                        <button class="modal-close" onclick="closeModal('resetPasswordModal')">×</button>
                    </div>
                    <p style="margin-bottom:16px;color:var(--text-muted)">Set a new password for <strong id="reset_user_name"></strong></p>
                    <form method="post">
                        <input type="hidden" name="action" value="reset_password">
                        <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
                        <input type="hidden" name="user_id" id="reset_user_id">
                        <div class="form-group">
                            <label>New Password (min 6 chars)</label>
                            <input type="text" name="new_password" minlength="6" required placeholder="Type new password" id="reset_pw_field">
                        </div>
                        <button class="btn">Reset Password</button>
                        <button type="button" class="btn btn-secondary" onclick="closeModal('resetPasswordModal')">Cancel</button>
                    </form>
                </div>
            </div>

        <?php else: ?>
            <h2><?= $edit ? '✏️ Edit Scholarship' : '➕ Add New Scholarship' ?></h2>
            <form method="post">
                <input type="hidden" name="action" value="<?= $edit ? 'update_scholarship' : 'add_scholarship' ?>">
                <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
                <?php if ($edit): ?><input type="hidden" name="scholarship_id" value="<?= (int)$edit['id'] ?>"><?php endif; ?>
                <div class="grid grid-2">
                    <div class="form-group"><label>Name</label><input name="name" value="<?= e($edit['name']??'') ?>" required></div>
                    <div class="form-group"><label>Institute</label><input name="institute" value="<?= e($edit['institute']??'') ?>" required></div>
                    <div class="form-group"><label>Country</label><input name="country" value="<?= e($edit['country']??'') ?>" required placeholder="e.g., USA, UK, Canada"></div>
                    <div class="form-group"><label>Degree Level</label>
                        <select name="degree_level" required>
                            <option value="">Select...</option>
                            <?php foreach (['Matric','Intermediate','Bachelor','Master','PhD','Any'] as $l): ?>
                                <option <?= ($edit['degree_level']??'')===$l?'selected':'' ?>><?= $l ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="form-group"><label>Min Percentage</label><input type="number" step="0.01" name="min_percentage" value="<?= e($edit['min_percentage']??'60') ?>" required></div>
                    <div class="form-group"><label>Deadline (optional)</label><input type="date" name="deadline" value="<?= e($edit['deadline']??'') ?>"></div>
                </div>
                <div class="form-group"><label>Benefits</label><textarea name="benefits" rows="3" required><?= e($edit['benefits']??'') ?></textarea></div>
                <div class="form-group"><label>Requirements</label><textarea name="requirements" rows="3" required><?= e($edit['requirements']??'') ?></textarea></div>
                <button class="btn"><?= $edit ? '💾 Update' : '➕ Add' ?></button>
                <?php if ($edit): ?><a href="?page=admin&tab=scholarships" class="btn btn-secondary">Cancel</a><?php endif; ?>
            </form>

            <h2 style="margin-top:32px">All Scholarships (<?= count(getAllScholarships()) ?>)</h2>
            <table>
                <thead><tr><th>Name</th><th>Institute</th><th>Country</th><th>Degree</th><th>Min %</th><th>Deadline</th><th>Actions</th></tr></thead>
                <tbody>
                <?php foreach (getAllScholarships() as $s): ?>
                    <tr>
                        <td><?= e($s['name']) ?></td>
                        <td><?= e($s['institute']) ?></td>
                        <td><?= country_flag($s['country']) ?> <?= e($s['country']) ?></td>
                        <td><?= e($s['degree_level']) ?></td>
                        <td><?= e($s['min_percentage']) ?>%</td>
                        <td><?= e($s['deadline'] ?? '—') ?></td>
                        <td style="display:flex;gap:6px">
                            <a href="?page=admin&tab=scholarships&edit=<?= (int)$s['id'] ?>" class="btn btn-secondary btn-sm">✏️</a>
                            <form method="post" style="display:inline" onsubmit="return confirm('Delete?')">
                                <input type="hidden" name="action" value="delete_scholarship">
                                <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
                                <input type="hidden" name="scholarship_id" value="<?= (int)$s['id'] ?>">
                                <button class="btn btn-danger btn-sm">🗑</button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>
    <?php
}
?>