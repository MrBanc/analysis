import r2pipe

r = r2pipe.open('/home/ben/codes/bordel/hw', flags=['-2'])
r.cmd('doo')
r.cmd('dm')
# parse pour trouver où est mappé le linker

r.cmd('s 0x403ff8')
i=r.cmd('p8 6')

print(i)
# retourner car c'est en little endian

# faire la diff entre les deux

# comparer avec l'information symbolique du linker

