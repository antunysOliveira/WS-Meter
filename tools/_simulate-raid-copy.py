# -*- coding: utf-8 -*-
# Simulate the raid copy output using fixture data based on user's examples.
CLASS_NAMES = {
    1:'Paladino',2:'Sacerdote',3:'Mago',4:'Barbaro',5:'Ladino',6:'Xama',
    7:'Dancarino',8:'Patrulheiro',9:'Druida',10:'Cav. Morte',11:'Necromante',
    12:'Bruxo',13:'Explorador',14:'Cacador',15:'Guarda',16:'Encantador',
    17:'Templario',18:'Cacique',19:'Inv. Feras',20:'Ceifeiro'
}

raid_list = [
    ('Welliton',436000),('Joones',256000),('Plzinxx',182000),('Uuu',160000),('Sun',152000),
    ('Solaron',146000),('Heige',141000),('Wsline',134000),('Donkja',128000),('Favor',123000),
    ('Capeta',119000),('Angelicais',118000),('Lingboo',93000),('Wsjunior',93000),('Alvarenga',89000),
    ('Really',85000),('Anemos',80000),('Voidcloth',79000),('Anttt',74000),('Necatrom',70000),
    ('Leone',69000),('Guagua',67000),('Liangzzi',67000),('Youla',64000),('Tigrez',61000),
    ('Rain',61000),('Kuriirin',55000),('Sicotin',49000),('Crasique',49000),('Mlkdopo',49000),
    ('Brutaly',39000),('Maranata',38000),('Loowuiu',38000),('Shadowkat',36000),('Yatobloodc',36000),
    ('Yza',35000),('Fatuo',34000),('Dirtydeep',34000),('Bjergsen',33000),('Bunequinho',33000),
    ('Dadiva',32000),('Wsmari',29000),('Atm',28000),('Aovelha',27000),('Kaguhia',27000),
    ('Swqs',24000),('Wsp',24000),('Centablg',23000),('Czz',22000),('Hybfff',21000),
    ('Bigcock',20000),('Herbertyx',19000),('Taosu',19000),('Oldphill',18000),('Lemon',17000),
    ('Vvvvvv',17000),('Alifxi',17000),('Bbq',17000),('Akkk',16000),('Godhell',16000),
    ('Reativo',16000),('Akvaic',15000),('Saicachorr',15000),('Xfenta',13000),('Novodk',11000),
    ('Bibobi',11000),('Gank',10000),('Aodebiao',9000),('Lingyoo',8000),('Liba',8000),
    ('Spoikazeus',7000),('Cronos',7000),('Zamioculca',6000),('Nerftotem',6000),('Ginny',5000),
    ('Mruu',4000),('Xamaxxx',3000),('Deusanegra',3000),('Inory',2000),('Sherry',2000),('Caloteira',802),
]

class_map = {}
for n in ['Donkja','Angelicais','Lingboo','Wsmari','Necatrom','Mlkdopo','Herbertyx','Bigcock','Zamioculca']:
    class_map[n] = 11
for n in ['Cucetinha','Gank','Xamaxxx','Ginny','Mengpo','Deusanegra','Mruu','Sherry','Inory','Caloteira']:
    class_map[n] = 6
for n in ['Oldphill','Bjergsen','Aodebiao','Maaiconpk','Dadiva','Liangzzi','Wsp','Rain','Bibobi']:
    class_map[n] = 4
for n in ['Lingyoo','Centablg','Horonvil','Loowuiu','Novodk','Swqs','Spoikazeus']:
    class_map[n] = 10

part = {}
for name, raid in raid_list:
    part.setdefault(name, {'name':name,'damage':raid,'damageRaid':raid,'received':0,'healingDone':0,'dps':0,'classId':class_map.get(name,0)})

heal_data = {
    'Donkja':(2238.44,7163),'Angelicais':(1239.90,9431),'Lingboo':(834.95,6464),
    'Wsmari':(701.79,53002),'Necatrom':(606.84,1871),'Mlkdopo':(560.25,4580),
    'Herbertyx':(272.03,14001),'Bigcock':(226.85,5164),'Zamioculca':(111.71,2292),
    'Cucetinha':(132.23,41068),'Gank':(108.47,161976),'Xamaxxx':(100.08,14104),
    'Ginny':(81.71,122721),'Mengpo':(72.39,39832),'Deusanegra':(46.01,19137),
    'Mruu':(34.89,63608),'Sherry':(31.17,714),'Inory':(16.67,49830),'Caloteira':(15.88,9032),
}
for name,(dps,heal) in heal_data.items():
    if name not in part:
        part[name]={'name':name,'damage':0,'damageRaid':0,'received':0,'healingDone':0,'dps':0,'classId':class_map.get(name,0)}
    part[name]['dps']=dps
    part[name]['healingDone']=heal

recv_data = {
    'Oldphill':72246,'Bjergsen':45410,'Aodebiao':38882,'Maaiconpk':36841,
    'Dadiva':33920,'Liangzzi':30449,'Wsp':24786,'Rain':24326,'Bibobi':22364,
    'Lingyoo':40271,'Centablg':38654,'Horonvil':37600,'Loowuiu':33082,
    'Novodk':29265,'Swqs':28135,'Spoikazeus':24475,
}
for name,recv in recv_data.items():
    if name not in part:
        part[name]={'name':name,'damage':0,'damageRaid':0,'received':0,'healingDone':0,'dps':0,'classId':class_map.get(name,0)}
    part[name]['received']=recv

lastParticipants = list(part.values())

def fmt_dmg_short(n):
    if not n or n <= 0: return '0'
    n = round(n)
    if n < 1000: return str(n)
    if n < 1000000: return str(round(n/1000))+'k'
    return (f"{n/1000000:.1f}").rstrip('0').rstrip('.') + 'M'

def fmt_num_pt(n, dec=0):
    if n is None: return '0'
    s = f"{n:,.{dec}f}"
    return s.replace(',','_').replace('.',',').replace('_','.')

def fmt_dmg_compact_pt(n):
    if not n or n <= 0: return '0'
    if n < 1000: return str(round(n))
    if n < 1000000: return f"{n/1000:.1f}".replace('.',',')+'k'
    return f"{n/1000000:.2f}".replace('.',',')+'M'

lines = []
ranked = sorted([p for p in lastParticipants if p['damageRaid']>0], key=lambda p: -p['damageRaid'])
lines += ['TOP DANO EM BOSS RAID','','TOP 10 EM BOSS']
for j,p in enumerate(ranked[:10]):
    lines.append(f"{j+1}- {p['name']} {fmt_dmg_short(p['damageRaid'])}")

by_class = {}
for p in ranked:
    if p['classId'] <= 0: continue
    by_class.setdefault(p['classId'], []).append(p)
class_ids = sorted(by_class.keys(), key=lambda c: -sum(x['damageRaid'] for x in by_class[c]))
lines += ['','TOP 5 POR CLASSE (dano em boss)']
for cid in class_ids:
    lines.append('')
    lines.append(CLASS_NAMES.get(cid,f'Classe {cid}'))
    for i,p in enumerate(by_class[cid][:5]):
        lines.append(f"{i+1}- {p['name']} {fmt_dmg_short(p['damageRaid'])}")

geral = sorted([p for p in lastParticipants if p['damage']>0], key=lambda p: -p['damage'])
if geral:
    lines += ['','____','','TOP DANO GERAL']
    for g,p in enumerate(geral):
        lines.append(f"{g+1}- {p['name']} {fmt_dmg_short(p['damage'])}")

heal_by_class = {}
for p in lastParticipants:
    if p['healingDone']<=0 or p['classId']<=0: continue
    heal_by_class.setdefault(p['classId'], []).append(p)
hcids = sorted(heal_by_class.keys(), key=lambda c: -sum(x['healingDone'] for x in heal_by_class[c]))
if hcids:
    lines += ['','____','','Cura por classe']
    for cid in hcids:
        cname = CLASS_NAMES.get(cid, f'Classe {cid}')
        members = sorted(heal_by_class[cid], key=lambda x: -x['healingDone'])
        lines.append('')
        lines.append(cname+':')
        for p in members:
            lines.append(f"- {p['name']} - DPS {fmt_num_pt(p['dps'],2)} | Cura {fmt_num_pt(p['healingDone'])}")

recv_by_class = {}
for p in lastParticipants:
    if p['received']<=0 or p['classId']<=0: continue
    recv_by_class.setdefault(p['classId'], []).append(p)
rcids = sorted(recv_by_class.keys(), key=lambda c: -sum(x['received'] for x in recv_by_class[c]))
if rcids:
    lines += ['','____','','Dano Recebido por classe']
    for cid in rcids:
        cname = CLASS_NAMES.get(cid, f'Classe {cid}')
        members = sorted(recv_by_class[cid], key=lambda x: -x['received'])
        lines.append('')
        lines.append(cname+':')
        for p in members:
            lines.append(f"- {p['name']} - {fmt_num_pt(p['received'])}")

m_dmg = max((p for p in lastParticipants if p['damage']>0), key=lambda p:p['damage'], default=None)
m_cur = max((p for p in lastParticipants if p['healingDone']>0), key=lambda p:p['healingDone'], default=None)
m_mas = max((p for p in lastParticipants if p['received']>0), key=lambda p:p['received'], default=None)
if m_dmg or m_cur or m_mas:
    lines += ['','____','','Resumo rapido:']
    if m_dmg: lines.append(f"Maior dano geral: {m_dmg['name']}: {fmt_dmg_compact_pt(m_dmg['damage'])}")
    if m_cur: lines.append(f"Maior cura: {m_cur['name']}")
    if m_mas: lines.append(f"Maior Masoquista: {m_mas['name']}")

print('\n'.join(lines))
