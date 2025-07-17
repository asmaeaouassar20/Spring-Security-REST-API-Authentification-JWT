####  Ce dépôt a pour but de démontrer l'intégration de Spring Security dans une application web Spring Boot utilisant Thymeleaf comme moteur de templates, plus précisement on a appris à :
- Créer des pages de **login** et **signup** personnalisées.
- Afficher les informations de l'utilisateur connecté.
- L'utilisateur connecté peut modifier ses informations personnelles.
- Un bouton de déconnexion

<br><br><br>
Par défaut, lorsque vous lancez l'application (`mvn spring-boot:run`), vous êtes redirigé automatiquement vers la page de login.
<img width="502" height="502" alt="image" src="https://github.com/user-attachments/assets/659ac19c-b1e2-4067-a2b9-cd9456623527" />

<br><br><br><br><br><br>

Un lien **"Register"** est disponible sur la page de login, permettant aux nouveaux utilisateurs de s'inscrire
<img width="502" height="502" alt="image" src="https://github.com/user-attachments/assets/bb731884-5dbc-4159-9882-bb5e02a8332b" />

<br><br><br><br><br><br>

Si une URL est inaccessible après connexion, une page d'erreur 404 s'affiche automatiquement.
<img width="450" height="450" alt="image" src="https://github.com/user-attachments/assets/1807f65f-63bc-490b-92eb-3506e1f442e9" />

<br><br><br><br><br><br>

Lorsqu'on tape le lien suivant dans le navigateur `http://localhost:8080`, 'application affiche par défaut cette **landing page** 
<img width="955" height="500" alt="image" src="https://github.com/user-attachments/assets/3b8b36bf-e03b-4d7b-af5d-5b56497eed71" />

<br><br><br><br><br><br>

La page de profil de **l'utilisateur connecté** est accessible à l'adresse :  `http://localhost:8080/profile`
<img width="500" height="500" alt="image" src="https://github.com/user-attachments/assets/317e90e1-da1a-4fc8-836a-989a8ed252df" />


<br><br><br><br><br><br>

**L'utilisateur connecté** peut mettre à jour ses informations via :  `http://localhost:8080/profile/update`
<img width="500" height="500" alt="image" src="https://github.com/user-attachments/assets/3ec8cd9d-2461-4c4c-8df1-ad0a2a4c330e" />



<br><br><br><br><br><br>

Si l'utilisateur clique sur le bouton de déconnexion, il sera redirigé vers la page de **login**


