for file in INSTALL LICENSE Makefile Makefile* *.cpp *.c *.hpp *.ac *.1 *.txt *.h
do
    echo file is $file
    ex +"%s///g" +"wq" $file
done

# Or
#   ed -s $file <<EOF
#   ,s///g
#   w
#   q
#   EOF
