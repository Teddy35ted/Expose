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
        Utilisateur.objects.create(nom=nom, mot_de_passe=mot_de_passe_hash.decode('utf-8'))  # Convertit le hash en chaîne

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
