for file in INSTALL LICENSE Makefile Makefile* *.cpp *.c *.hpp *.ac *.1 *.txt *.h
do
    echo file is $file
    ex +"%s/
done

# Or
#   ed -s $file <<EOF
#   ,s/
#   w
#   q
#   EOF