from django.shortcuts import render, redirect
from .models import Utilisateur
from .utils import hash_password, check_password  # Importe les fonctions de hachage et vérification

# Vue pour l'inscription
def signin(request):
    if request.method == 'POST':
        nom = request.POST.get('nom')
        mot_de_passe = request.POST.get('mot_de_passe')

        # Vérifie si l'utilisateur existe déjà
        if Utilisateur.objects.filter(nom=nom).exists():
            return render(request, 'signin.html', {'error': 'Ce nom d\'utilisateur est déjà pris.'})

        # Hash le mot de passe avant de l'enregistrer
        mot_de_passe_hash = hash_password(mot_de_passe)

        # Crée un nouvel utilisateur
        Utilisateur.objects.create(nom=nom, mot_de_passe=mot_de_passe_hash.decode('utf-8'))  # Convertit en chaîne

        return redirect('login')  # Redirige vers la page de connexion

    return render(request, 'signin.html')

# Vue pour la connexion
def user_login(request):
    if request.method == 'POST':
        nom = request.POST.get('nom')
        mot_de_passe = request.POST.get('mot_de_passe')

        try:
            utilisateur = Utilisateur.objects.get(nom=nom)
        except Utilisateur.DoesNotExist:
            return render(request, 'login.html', {'error': 'Nom d\'utilisateur ou mot de passe incorrect.'})

        # Vérifie si le mot de passe correspond
        if check_password(mot_de_passe, utilisateur.mot_de_passe):
            # Stocke le nom d'utilisateur dans la session
            request.session['username'] = utilisateur.nom
            return redirect('home')  # Redirige vers la page d'accueil
        else:
            return render(request, 'login.html', {'error': 'Nom d\'utilisateur ou mot de passe incorrect.'})

    return render(request, 'login.html')

# Vue pour la page d'accueil
def home(request):
    # Récupère le nom d'utilisateur depuis la session
    username = request.session.get('username')

    if username:
        # Récupère l'utilisateur depuis la base de données
        utilisateur = Utilisateur.objects.get(nom=username)
        return render(request, 'home.html', {'utilisateur': utilisateur})
    else:
        # Redirige vers la page de connexion si l'utilisateur n'est pas connecté
        return redirect('login')

# Vue pour la déconnexion
def user_logout(request):
    if 'username' in request.session:
        del request.session['username']
    return redirect('login')


def password_reset_request(request):
    if request.method == 'POST':
        nom = request.POST.get('nom')  # Nom d'utilisateur ou email
        try:
            utilisateur = Utilisateur.objects.get(nom=nom)
            # Redirige vers la page de réinitialisation avec l'ID de l'utilisateur
            return redirect('password_reset_confirm', user_id=utilisateur.id)
        except Utilisateur.DoesNotExist:
            return render(request, 'password_reset_request.html', {'error': 'Aucun utilisateur trouvé avec ce nom.'})

    return render(request, 'password_reset_request.html')

def password_reset_confirm(request, user_id):
    try:
        utilisateur = Utilisateur.objects.get(id=user_id)
    except Utilisateur.DoesNotExist:
        return render(request, 'password_reset_confirm.html', {'error': 'Utilisateur non trouvé.'})

    if request.method == 'POST':
        nouveau_mot_de_passe = request.POST.get('nouveau_mot_de_passe')
        confirm_mot_de_passe = request.POST.get('confirm_mot_de_passe')

        if nouveau_mot_de_passe != confirm_mot_de_passe:
            return render(request, 'password_reset_confirm.html', {'error': 'Les mots de passe ne correspondent pas.'})

        # Hash le nouveau mot de passe
        utilisateur.mot_de_passe = hash_password(nouveau_mot_de_passe)
        utilisateur.save()

        return render(request, 'password_reset_confirm.html', {'success': 'Votre mot de passe a été réinitialisé avec succès.'})

    return render(request, 'password_reset_confirm.html', {'user_id': user_id})


def password_change(request):
    if request.method == 'POST':
        nom = request.POST.get('nom')
        ancien_mot_de_passe = request.POST.get('ancien_mot_de_passe')
        nouveau_mot_de_passe = request.POST.get('nouveau_mot_de_passe')
        confirm_mot_de_passe = request.POST.get('confirm_mot_de_passe')

        try:
            utilisateur = Utilisateur.objects.get(nom=nom)
        except Utilisateur.DoesNotExist:
            return render(request, 'password_change.html', {'error': 'Nom d\'utilisateur incorrect.'})

        # Vérifie l'ancien mot de passe
        if not check_password(ancien_mot_de_passe, utilisateur.mot_de_passe):
            return render(request, 'password_change.html', {'error': 'Ancien mot de passe incorrect.'})

        # Vérifie que les nouveaux mots de passe correspondent
        if nouveau_mot_de_passe != confirm_mot_de_passe:
            return render(request, 'password_change.html', {'error': 'Les nouveaux mots de passe ne correspondent pas.'})

        # Hash le nouveau mot de passe
        nouveau_mot_de_passe_hash = hash_password(nouveau_mot_de_passe)

        # Met à jour le mot de passe dans la base de données
        utilisateur.mot_de_passe = nouveau_mot_de_passe_hash.decode('utf-8')  # Convertit en chaîne
        utilisateur.save()

        return render(request, 'password_change.html', {'success': 'Votre mot de passe a été modifié avec succès.'})

    return render(request, 'password_change.html')