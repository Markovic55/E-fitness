from flask import Flask, render_template, jsonify, request, url_for, redirect, session
from flask_uploads import UploadSet, IMAGES, configure_uploads
from pymongo import MongoClient
from bson import ObjectId

from pprint import pprint
import hashlib,string,json,datetime

"""
Da bi uopste radilo prvo morate da pokrenete fajl server_console.bat 
u njemu "cd src" pa "python main.py"
"""
client = MongoClient('mongodb+srv://name:<paswword>@cluster0-mwhyq.mongodb.net/<baza>?retryWrites=true&w=majority') #ovo je konekcioni
#string za povezivanje na mongo 
db = client.get_database("db_fitness") #vasa baza
kupljeni = db.kupljeni_proizvodi #
users = db.users                  #
items = db.proizvodi              # kolekcije iz baze tj. tabele
komentari = db.komentari         #



now = datetime.datetime.now() #trenutni datum

app = Flask(__name__)                         #
app.config['SECRET_KEY'] = 'NEKI RANDOM STRING'#
photos = UploadSet('photos', IMAGES)            # Ovo su standard stvari za flask i da bi mogli slike da ubacujete
app.config['UPLOADED_PHOTOS_DEST'] = 'static'  #
configure_uploads(app, photos)                #

@app.route('/')      #i na rutu "/" i "/index" ce se pokretati index strana
@app.route('/index') 
def index():
	#Odmah na startu da znate da je admin direktno u bazu ubacen samo sam mu heshovao sifru printovao i kopirao is cmd-a
	#Username:admin i password:admin
	#moze da brise korisnike i doda komentar
	if 'username' in session:    #Proveravamo da li je user ulogovan

		ulogovan='jeste' #setovanje varijable na jeste jer cemo to koristiti u template-u kao razgranicavanje ko jeste a ko nije
		
		return render_template('index.html', ulogovan=ulogovan) # ovde se salju zadate varijable na
		#index.html za proveravanje da li je ulogovan ili nije, jer se razlicit sadrzaj plasira onom koji jeste i onom koji nije
	else:
		ulogovan='nije'
		return render_template('index.html', ulogovan=ulogovan )

@app.route('/registracija',methods = ["GET"])
def registracija():
	if request.method == 'GET':  #Ova strana nam pristize iz dugmeta za registraciju href="" sto je GET metoda
		return render_template('registracija.html') #Vracamo samo stranu registracija.html na kojoj su dva linka za kupca i prodavca
		
	
#KUPAC	
@app.route('/registerk', methods = ['GET', 'POST'])
def registerk():

	if request.method == 'GET':
		return render_template('register.html') #Isto vracamo samo html stranu jer nismo poslali nikakve podatke POST metodom
		#vec GET metodom tipa ukucali u url-u ili iz dugmeta href = "" opcijom
	else:
		#Ovo su podaci koji su dosli sa forme, request.form nam omogucava da pokupimo sta je korisnik uneo
		email = request.form['username']
		type = 'kupac'                   
		password = request.form['password']
		ime = request.form['ime']
		prezime = request.form['prezime']
		brojkartice = request.form['brojkartice']
		adresa = request.form['adresa']
		#hesiranje sifre 
		hash_object = hashlib.sha256(password.encode())
		password_hashed = hash_object.hexdigest()

		username = email; #namecemo email kao username
		#pretrazivanje korisnika po datom username-u i ako vec postoji takav onemogucavamo dalji rad 
		u = users.find_one({'username': username}) 
		if u is not None:
			return 'User vec postoji!'
		#key:value za ubacivanje podataka u kolekciju, levo = stvarni nazivi u kolekciji, desno = varijable koje smo pokupili
		novi_user = {
			'ime': ime,
			'prezime': prezime,
			'brojkartice':brojkartice,
			'adresa':adresa,
			'username': username,
			'password': password_hashed,
			'pare':10,
			'type': type
			
		}
		users.insert_one(novi_user) #ubacivanje u kolekciju

		return redirect(url_for('login')) #saljemo korisnika na login rutu koja otvara stranu
#PRODAVAC
@app.route('/registerp', methods = ['GET', 'POST'])
def registerp():
	#Isto ko kupac
	if request.method == 'GET':
		return render_template('registerp.html')
	else:
		email = request.form['username']
		type = 'prodavac'
		password = request.form['password']
		ime = request.form['ime']
		prezime = request.form['prezime']
		brojkartice = request.form['brojkartice']
		adresa = request.form['adresa']
		kompanija=request.form['kompanija']
		
		hash_object = hashlib.sha256(password.encode())
		password_hashed = hash_object.hexdigest()
		
		username = email
		u = users.find_one({'username': username})

		if u is not None:
			return 'User vec postoji!'
		
		novi_user = {
			'ime': ime,
			'prezime': prezime,
			'brojkartice':brojkartice,
			'adresa':adresa,
			'username': username,
			'password': password_hashed,
			'pare':0,
			'kompanija': kompanija,
			'type': type,
			'brprodaja':0,
			'prosecnap':0
			
		}
		users.insert_one(novi_user)

		return redirect(url_for('login'))
		
@app.route('/login', methods = ['GET', 'POST'])
def login():

	if 'username' in session:
		return 'Vec ste ulogovani!' #ako je u sesiji vec je ulogovan

	if request.method == 'GET':
		return render_template('login.html')

	username = request.form['username'] #Uneti username iz forme
	password = request.form['password'] #Uneti password iz forme
	
		
	
	hash_object = hashlib.sha256(password.encode())
	password_hashed = hash_object.hexdigest()
	#trazenje korisnika(users kolekcija) po username-u i sifri koji su upisani u formu 
	user = users.find_one({'username': username, 'password': password_hashed})
	if user is None:
		return 'Pogresan username ili password!' #Ako se ne poklapaju znaci da je korisnik pogresio
	#u suprotnom stavljamo ga u session sto znaci da je ulogovan
	session['username'] = username 
	session['type'] = user['type']
	return redirect(url_for('index')) #otvaranje index rute koja otvara stranu na rutu se salje da bi se odradila provera kroz funkciju
	#npr. kog je tipa korisnik koji dolazi da bi mu se plasirao ta i ta strana itd..
	
@app.route('/logout') 
def logout():
	if 'username' not in session:
		return 'Niste ulogovani, ne mozete se izlogovati!'
	
	session.pop('username', None) #.pop metoda za izbacivanje iz sessiona(logout)
	session.pop('type', None)
	return redirect(url_for('index'))
	
@app.route('/myprofile') #nema method za GET ili POST jer je GET podrazumevan ako nema nista a sve dolazi GET methodom na myprofile
def moj_profil():
	if 'username' not in session:
		return redirect(url_for('login'))
		
	trenutni_username = session['username'] #vadjenje username-a iz sessiona(ulogovani)
	trenutni_user = users.find_one({'username': trenutni_username}) #trazenje ulogovanog usera po username-u u kolekciji users
	#Ako se ne poklapaju ulogovani username sa nekim od username-ova iz users docice do greske 
	if trenutni_user is None:
		session.pop('username', None)
		session.pop('type', None)
		return 'Doslo je do greske! Ulogujte se ponovo!'
		
	all_items = items.find({"owner": session['username']}).sort('popularnost',-1) #Itemi imaju kolonu owner i trazimo ulogovanog i
	#sve iteme koje on ima sa popularnoscu od vece ka manjoj
	lista_itema = [item for item in all_items] #list-comprehension za pravljenje liste svih item-a
	for item in lista_itema:
		item['_id'] = str(item['_id']) #prebacivanje id item-a u string
		
	kupljeni_items = db.kupljeni_proizvodi.find({"buyer": session['username']}) #U kolekciji kupljeni_proizvodi imamo kupca kojeg ovde
	#trazimo da li je to taj koji je ulogovan trenutno
	lista_kupljenih_itema = [item for item in kupljeni_items] #Lista kupljenih itema
	for kupljeni in lista_kupljenih_itema:
		kupljeni['_id'] = str(kupljeni['_id'])

	kupljeni_itemi = db.kupljeni_proizvodi.find({"owner": session['username']}) 
	lista_kupljenih_item = [item for item in kupljeni_itemi] #Lista itema iz kupljenih koji su bili u vlasnistvu 
	#ulogovanog prodavca
	for kupljeni in lista_kupljenih_item:
		kupljeni['_id'] = str(kupljeni['_id'])

	#slanje user varijable da bi videli cije item-e da predstavimo	
	#items svi temi
	#items2 itemi kupca iz kupljenih itema
	#items3 itemi koje je prodao owner
	return render_template('profil.html',username = trenutni_username,user = trenutni_user , items = lista_itema ,
		items2= lista_kupljenih_itema,items3= lista_kupljenih_item)
	
@app.route('/items/<id>') #id je poslat iz href= "" iz all_items.html
def pojedinacni_item(id):
	trenutni_username = session['username']
	trenutni_user = users.find_one({'username': trenutni_username})
	trazeni_item = items.find_one({'_id': ObjectId(id)})
	iditema=trazeni_item['_id']
	prodavac=trazeni_item['owner']

	if trazeni_item is None:
		return 'Item ne postoji!'
    #ako je kupac taj koji je ulogovan i dosao je na stranu povecavaju se visits tom item-u
	if session['type'] == 'kupac':
		nove_posete = trazeni_item['visits'] + 1
		items.update_one({"_id": ObjectId(id)}, {"$set": {'visits': nove_posete}})

	kupljeni_items = db.kupljeni_proizvodi.find({"owner": trenutni_username})
	lista_kupljenih_itema = [item for item in kupljeni_items]

	for kupljeni in lista_kupljenih_itema:
		kupljeni['_id'] = str(kupljeni['_id'])
	#prikaz svih komentara iz kolekcije komentari	
	svi_komentari = db.komentari.find({'id': iditema })
	lista_komentara = [komentar for komentar in svi_komentari]
	for komentar in lista_komentara:
		komentar['_id'] = str(komentar['_id'])
	prodavacitema=users.find_one({'username':prodavac})
	brprodaja=prodavacitema['brprodaja']
	brojkomentara=trazeni_item['brojkomentara']
	popularnost=int(trazeni_item['visits'])+brojkomentara*10+brprodaja*15
	items.update_one({'_id':ObjectId(id)},{'$set':{'popularnost':popularnost}})	
	return render_template('item.html',prodavac=prodavacitema, item = trazeni_item,
		komentar=lista_komentara, user = trenutni_user,item2=lista_kupljenih_itema, id = id)

@app.route('/sellers/<id>')
def seller_page(id):
	suma=0
	brojac=0
	suma=0
	brojac=0
	trazeni_user = users.find_one({'_id': ObjectId(id)})
	ime=trazeni_user['username']
	all_items=items.find({'owner':ime})
	lista_itema = [item for item in all_items]
	for item in lista_itema:
		item['_id'] = str(item['_id'])
		suma=suma+item['popularnost']
		brojac=brojac+1
	if brojac>0:
		prosecnap=suma/brojac
		users.update_one({'username': ime},{'$set':{'prosecnap':prosecnap}})
	return render_template('seller.html', items = lista_itema ,user=ime)
	
	
@app.route('/all-items')
def svi_itemi():
	# izlistavanje svih proizvoda
	all_items = items.find({}).sort('popularnost', -1) # all_items = lista prozivoda iz kolekcije items i sortirani po popularnoscu
	lista_itema = [item for item in all_items]
	for item in lista_itema:
		item['_id'] = str(item['_id'])
	return render_template('all_items.html', items = lista_itema)
@app.route('/sellers')
def svi_prodavci():
	all_sellers = users.find({'type':'prodavac'}).sort('prosecnap',-1)
	lista_prodavaca = [user for user in all_sellers]
	for user in lista_prodavaca:
		user['_id'] = str(user['_id'])
	
	return render_template('all_sellers.html', users = lista_prodavaca)
	
	
@app.route('/dodaj-item', methods = ['POST'])
def dodavanje():
			#  dodavanje proizvoda isto kao i za registraciju kupca ili prodavca, isti princip
	if 'username' not in session:
		return redirect(url_for('login'))
		
	if session['type'] != 'prodavac':
		return 'Niste prodavac!'
	#key:value za ubacivanje podataka u kolekciju, levo = stvarni nazivi u kolekciji, desno = varijable koje smo pokupili
	novi_item = {
		'name': request.form['name'],
		'price': request.form['price'],
		'desc': request.form['desc'],
		'qtt': request.form['qtt'],
		'visits': 0,
		'owner': session['username'],
		'popularnost':0,
		'brojkomentara':0
	}
	if 'slika' in request.files:
		photos.save(request.files['slika'], 'img', request.form['name'] + '.png')

	items.insert_one(novi_item)
	return redirect(url_for('moj_profil'))
	

@app.route('/dodajpare' , methods=['POST'])
def dodaj_pare():
	#isto kao i za dodaj kolicinu, samo trazimo korisnika u kolekciji users i azuriramo stanje para +100 moze se menjati po zelji
	kome=session['username']
	trenutno_stanje= users.find_one({'username': kome},{'pare':1 , '_id':0})
	trenutno_stanje=trenutno_stanje['pare']
	trenutno_stanje=int(trenutno_stanje)+100
	users.update_one({'username': kome},{'$set' : {'pare': trenutno_stanje}})
	return redirect(url_for('moj_profil'))
@app.route('/dodajkolicinu' , methods=['POST'])
def dodaj_kolicinu():
	#dodavanje kolicine za proizvode, kome= kom proizvodu dodajes kolicinu a 'kojiitem' hvatamo kao podatak iz forme
	if request.method == 'POST':
		kome=request.form['kojiitem']
		trenutno_stanje1= items.find_one({'name': kome }) # pronalazimo proizvod u kolekciji items
		trenutno_stanje1=trenutno_stanje1['qtt'] # trenutno stanje 
		kolicina=request.form['kolicina']# kolicina koja ce biti unesena

		trenutno_stanje1=int(trenutno_stanje1)+int(kolicina)# sabiramo trenutno stanje i novu unesenu kolicinu

		items.update_one({'name': kome},{'$set' : {'qtt': trenutno_stanje1}}) #update stanja
		return redirect(url_for('moj_profil'))
@app.route('/izbrisi-item' , methods=['POST'])
def izbris_item():
	# brisanje proizvoda, kome dodeljujemo podakat 'kojiitem' i radimo delete_one
		kome=request.form['kojiitem']	
		items.delete_one({'name': kome})
		return redirect(url_for('moj_profil'))
@app.route('/kupi' , methods=['POST'])
def kupi_item():
	# kupovina proizvoda, kupimo podatke
	if request.method == 'POST':
		kome=request.form['kojiitem']
		proizvod= items.find_one({'name': kome })
		iditema=proizvod['_id']
		cena=proizvod['price']
		prodavac=proizvod['owner']
		kolicinaproizvoda=proizvod['qtt']
		kolicina=request.form['kolicina']
		kupac=session['username']
		ostalakolicina=int(kolicinaproizvoda)-int(kolicina)
		kupac1=users.find_one({'username': kupac})
		prodavac1=users.find_one({'username':prodavac})
		idp=prodavac1['_id']
		stanjenovcak=kupac1['pare']
		stanjenovcap=prodavac1['pare']
		cenaprozivoda=int(cena)*int(kolicina)
		brprodaja=prodavac1['brprodaja']

		if ostalakolicina>=0 : # provera da li mozemo da kupimo proizvod,
			if cenaprozivoda > stanjenovcak: # da li je cena proizvoda veca nego sto korisnik ima para na stanju
				return('nemate dovoljno novca na racunu')
			else:
				stanjenovcak=int(stanjenovcak)-cenaprozivoda # oduzimanje para sa stanja korisnika nakon kupovine
				stanjenovcap=int(stanjenovcap)+cenaprozivoda
				brprodaja=int(brprodaja)+1 # evidencija koliko je puta prodat item, pri svakoj kupovini +1
				
				name=proizvod['name']
				owner=proizvod['owner']
				kol=kolicina
				kupac=kupac1['username']
				kupljeni_item = {
					'id': iditema,
					'id2': idp,
					'buyer':kupac,
					'name': name,
					'price': cenaprozivoda,
					'qtt': kol,
					'owner': owner,
					'time': now.strftime("%Y-%m-%d %H:%M")
				}

				items.update_one({'name': kome},{'$set' : {'qtt': ostalakolicina}}) # update za kolicinu
				users.update_many({'username':prodavac},{'$set' : {'pare':stanjenovcap ,'brprodaja': brprodaja}}) 
				users.update_one({'username': kupac},{'$set' : {"pare":stanjenovcak }})
				kupljeni.insert_one(kupljeni_item)
				return redirect(url_for('moj_profil'))	
		else:
			return 'nema toliko proizvoda na stanju'
@app.route('/dodaj-komentar' , methods=['POST'])
def dodaj_komentar():
	#dodavanje komentara, kome= name'kojiitem' koji je se nalazi na stranici item.html u formi, pogledati stranicu item.html
		kome=request.form['kojiitem']
		proizvod= items.find_one({'name': kome })
		ime=session['username']
		tip=session['type']
		iditema=proizvod['_id']
		komentar=request.form['komentar']
		novi_komentar = {
			'id':iditema,
			'nameitem': kome,
			'comment':komentar,
			'name':ime,
			'type': tip,
			'time': now.strftime("%Y-%m-%d %H:%M")

		}
		komentari.insert_one(novi_komentar) # ubacivanje komentar
		brojkomentara=int(proizvod['brojkomentara'])+1 # dodavanje komentara na proizvod
		print('brojkomentara')
		items.update_one({'_id':iditema},{'$set':{'brojkomentara':brojkomentara}}) #update za komentar
		return redirect(url_for('pojedinacni_item', id = iditema))
@app.route('/users')
def svi_korisnici():
	# izlistavanje svih korisnika, trenunutni_user je onaj koji je u sesiji po 'vrsti'
	trenutni_user=session['type']
	all_users = users.find({})# kazemo da je all_users niz koji cemo pronaci u bazi kroz 'for' 
	lista_svih = [user for user in all_users]
	for user in lista_svih:
		user['_id'] = str(user['_id']) # pretvranje objekta u string
	return render_template('users.html', users = lista_svih ,tuser=trenutni_user)	
@app.route('/users/<id>')
def pojedinacni_user(id):

	trenutni_user=session['type']
	trazeni_user = users.find_one({'_id': ObjectId(id)})
	if trazeni_user is None:
		return 'Korisnik ne postoji!'
	
	return render_template('user.html', user = trazeni_user, id = id, tuser=trenutni_user)

@app.route('/izbrisi-korisnika' , methods=['POST'])
def izbris_korisnika():
	#  brisanje korisnika iz baze
		ime=request.form['ime']	#namecemo ime kao 'ime' iz forme po 'name'
		vrsta=request.form['vrsta']
		
		if vrsta == 'kupac': # ako je vrsta korisnika kupac obrisi mu nalog	
			users.delete_one({'username': ime})
		elif vrsta == 'prodavac': # ako je vrsta korisnika prodavac obrisi mu nalog i sve njegove proizvode
			users.delete_one({'username': ime})
			items.delete_many({'owner':ime})
	
		return redirect(url_for('svi_korisnici'))

if __name__ == '__main__':
	app.run(debug = True)
