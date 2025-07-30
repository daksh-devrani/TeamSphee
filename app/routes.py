from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.utils import generate_verification_token, confirm_verification_token
from app.models import User, Team, TeamMember, Project, Task, Comment, TeamInvitation
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from app.email_utils import send_email
from app.invitation import create_and_send_invite


bp = Blueprint('main', __name__)


@bp.route('/')
def index():
    return redirect(url_for('main.login'))


@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('main.dashboard'))
        flash('Invalid credentials')
    return render_template('login.html')


@bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered.', 'danger')
            return redirect(url_for('main.signup'))

        new_user = User(name=name, email=email, password=generate_password_hash(password), is_verified=False)
        db.session.add(new_user)
        db.session.commit()

        token = generate_verification_token(new_user.email)
        verify_url = url_for('main.verify_email', token=token, _external=True)
        send_email(
            new_user.email,
            'Verify your TeamSphee Account',
            f'Hi {new_user.name},\n\nPlease click this link to verify your email:\n\n{verify_url}\n\nThanks!'
        )

        flash('Signup successful! Check your email to verify your account.', 'success')
        return redirect(url_for('main.login'))

    return render_template('signup.html')


@bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.login'))


@bp.route('/dashboard')
@login_required
def dashboard():
    if not current_user.is_verified:
        flash('Please verify your email before accessing the dashboard.', 'warning')
        return redirect(url_for('main.login'))

    teams = TeamMember.query.filter_by(user_id=current_user.id).all()
    my_tasks = Task.query.filter_by(assignee_id=current_user.id).all()
    return render_template('dashboard.html', teams=teams, my_tasks=my_tasks)


@bp.route('/team/new', methods=['POST'])  # Remove GET
@login_required
def new_team():
    name = request.form['name']
    team = Team(name=name, created_by_id=current_user.id)
    db.session.add(team)
    db.session.commit()
    team_member = TeamMember(user_id=current_user.id, team_id=team.id, role='admin')
    db.session.add(team_member)
    db.session.commit()
    return redirect(url_for('main.team', team_id=team.id))


@bp.route('/team/<int:team_id>')
@login_required
def team(team_id):
    team = Team.query.get_or_404(team_id)
    if not TeamMember.query.filter_by(user_id=current_user.id, team_id=team_id).first():
        flash('Access denied')
        return redirect(url_for('main.dashboard'))
    projects = Project.query.filter_by(team_id=team_id).all()
    return render_template('team.html', team=team, projects=projects)


@bp.route('/team/<int:team_id>/invite', methods=['POST'])
@login_required
def invite_member(team_id):
    team = Team.query.get_or_404(team_id)
    if TeamMember.query.filter_by(user_id=current_user.id, team_id=team_id, role='admin').first():
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            if not TeamMember.query.filter_by(user_id=user.id, team_id=team_id).first():
                team_member = TeamMember(user_id=user.id, team_id=team_id, role='member')
                db.session.add(team_member)
                db.session.commit()
                flash('Member invited')
            else:
                flash('User already in team')
        else:
            flash('User not found')
    else:
        flash('Only admins can invite members')
    return redirect(url_for('main.team', team_id=team_id))


@bp.route('/project/new', methods=['POST'])
@login_required
def new_project():
    team_id = request.form['team_id']
    if TeamMember.query.filter_by(user_id=current_user.id, team_id=team_id, role='admin').first():
        name = request.form['name']
        project = Project(name=name, team_id=team_id)
        db.session.add(project)
        db.session.commit()
        return redirect(url_for('main.project', project_id=project.id))
    flash('Only admins can create projects')
    return redirect(url_for('main.team', team_id=team_id))


@bp.route('/project/<int:project_id>')
@login_required
def project(project_id):
    project = Project.query.get_or_404(project_id)
    team_member = TeamMember.query.filter_by(user_id=current_user.id, team_id=project.team_id).first()
    if not team_member:
        flash('Access denied')
        return redirect(url_for('main.dashboard'))
    tasks = Task.query.filter_by(project_id=project_id).all()
    members = TeamMember.query.filter_by(team_id=project.team_id).all()
    return render_template('project.html', project=project, tasks=tasks, members=members)


@bp.route('/task/new', methods=['POST'])
@login_required
def new_task():
    project_id = request.form['project_id']
    project = Project.query.get_or_404(project_id)
    if TeamMember.query.filter_by(user_id=current_user.id, team_id=project.team_id).first():
        title = request.form['title']
        description = request.form['description']
        due_date = request.form['due_date']
        priority = request.form['priority']
        assignee_id = request.form['assignee_id']
        task = Task(
            title=title,
            description=description,
            due_date=datetime.strptime(due_date, '%Y-%m-%d') if due_date else None,
            priority=priority,
            project_id=project_id,
            assignee_id=assignee_id if assignee_id else None
        )
        db.session.add(task)
        db.session.commit()
        return redirect(url_for('main.project', project_id=project_id))
    flash('Access denied')
    return redirect(url_for('main.dashboard'))


@bp.route('/task/<int:task_id>/update_status', methods=['POST'])
@login_required
def update_task_status(task_id):
    task = Task.query.get_or_404(task_id)
    if task.assignee_id == current_user.id or TeamMember.query.filter_by(user_id=current_user.id, team_id=task.project.team_id).first():
        task.status = request.form['status']
        db.session.commit()
        return redirect(url_for('main.project', project_id=task.project_id))
    flash('Access denied')
    return redirect(url_for('main.dashboard'))


@bp.route('/task/<int:task_id>/comment', methods=['POST'])
@login_required
def add_comment(task_id):
    task = Task.query.get_or_404(task_id)
    if TeamMember.query.filter_by(user_id=current_user.id, team_id=task.project.team_id).first():
        content = request.form['content']
        comment = Comment(content=content, task_id=task_id, user_id=current_user.id)
        db.session.add(comment)
        db.session.commit()
        return redirect(url_for('main.project', project_id=task.project_id))
    flash('Access denied')
    return redirect(url_for('main.dashboard'))


@bp.route('/verify/<token>')
def verify_email(token):
    email = confirm_verification_token(token)
    if not email:
        flash("Verification link is invalid or has expired.", "danger")
        return redirect(url_for("main.login"))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("main.login"))

    if user.is_verified:
        flash("Account already verified. Please login.", "info")
    else:
        user.is_verified = True
        db.session.commit()
        flash("Your account has been verified!", "success")

    return redirect(url_for("main.login"))


@bp.before_request
def restrict_unverified_users():
    if current_user.is_authenticated \
            and not current_user.is_verified \
            and request.endpoint not in ['main.verify_email', 'main.logout', 'main.login', 'main.signup']:
        flash('Please verify your email to access the site.', 'warning')
        return redirect(url_for('main.login'))


@bp.route('/invite/<int:team_id>', methods=['POST'])
@login_required
def invite_user(team_id):
    team = Team.query.get_or_404(team_id)

    if team.owner_id != current_user.id:
        return "Unauthorized", 403

    email = request.form['email']
    role = request.form.get('role', 'member')  # Optional role

    create_and_send_invite(team, email, role)
    return f"Invitation sent to {email}"


@bp.route('/accept-invite/<token>')
@login_required
def accept_invite(token):
    # Look up invitation
    invitation = TeamInvitation.query.filter_by(token=token).first()

    # Validate token
    if not invitation:
        flash("Invalid invitation token.", "danger")
        return redirect(url_for('main.dashboard'))

    if invitation.expires_at < datetime.utcnow():
        flash("This invitation has expired.", "warning")
        return redirect(url_for('main.dashboard'))

    if invitation.is_accepted:
        flash("This invitation has already been accepted.", "info")
        return redirect(url_for('main.dashboard'))

    # Check if already a member
    existing = TeamMember.query.filter_by(user_id=current_user.id, team_id=invitation.team_id).first()
    if existing:
        flash("You are already a member of this team.", "info")
        return redirect(url_for('main.dashboard'))

    # Create membership
    membership = TeamMember(
        user_id=current_user.id,
        team_id=invitation.team_id,
        role='member'  # Force member role even if invitation had something else
    )
    db.session.add(membership)

    # Mark invitation as accepted
    invitation.is_accepted = True
    db.session.commit()

    flash(f"You've successfully joined the team: {membership.team.name}!", "success")
    return redirect(url_for('main.dashboard'))
