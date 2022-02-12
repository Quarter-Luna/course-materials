// bhg-scanner/scanner.go modified from Black Hat Go > CH2 > tcp-scanner-final > main.go
// Code : https://github.com/blackhat-go/bhg/blob/c27347f6f9019c8911547d6fc912aa1171e6c362/ch-2/tcp-scanner-final/main.go
// License: {$RepoRoot}/materials/BHG-LICENSE
// Useage:
// {TODO 1: FILL IN}
// Ian Moon
// COSC 4010
// 02/11/21

package scanner

import (
	"fmt"
	"net"
	"sort"
	"time"
)

//complete TODO 3 : ADD closed ports; currently code only tracks open ports
var openports []int  // notice the capitalization here. access limited!
var closedports []int


func worker(ports, results chan int) {
	var timeout = time.Duration(1) * time.Second
	for p := range ports {
		address := fmt.Sprintf("scanme.nmap.org:%d", p)    
		conn, err := net.DialTimeout("tcp", address, timeout) //complete TODO 2 : REPLACE THIS WITH DialTimeout (before testing!)
		if err != nil { 
			results <- 0
			continue
		}
		conn.Close()
		results <- p
	}
}

// for Part 5 - consider
// easy: taking in a variable for the ports to scan (int? slice? ); a target address (string?)?
// med: easy + return  complex data structure(s?) (maps or slices) containing the ports.
// hard: restructuring code - consider modification to class/object 
// No matter what you do, modify scanner_test.go to align; note the single test currently fails

func PortScan(port []int, address string, result chan int) chan int {
	for i := range port {
		compaddress := fmt.Sprintf("%s%d", address, port[i])
		conn, err := net.DialTimeout("tcp", compaddress, time.Duration(1) * time.Second)
		if err != nil {
			result <- 0
			continue
		}
		conn.Close()
		result <- i
	}
	return result
}

func PortScanner() int {  

	ports := make(chan int, 1024)   // TODO 4: TUNE THIS FOR CODEANYWHERE / LOCAL MACHINE
	results := make(chan int)

	for i := 0; i < cap(ports); i++ {
		go worker(ports, results)
	}

	go func() {
		for i := 1; i <= 1024; i++ {
			ports <- i
		}
	}()

	for i := 0; i < 1024; i++ {
		port := <-results
		if port != 0 {
			openports = append(openports, port)
		} else {
			closedports = append(closedports, port)
		}
	}

	close(ports)
	close(results)
	sort.Ints(openports)
	sort.Ints(closedports)

	//complete TODO 5 : Enhance the output for easier consumption, include closed ports

	fmt.Printf("Open-------------------------------------------------------\n")

	for _, port := range openports {
		fmt.Printf("%d open\n", port)
	}

	fmt.Printf("Closed-----------------------------------------------------\n")

	fmt.Printf("Number of closed ports: %d\n", len(closedports))

	return (len(openports) + len(closedports)) //complete TODO 6 : Return total number of ports scanned (number open, number closed); 
	//you'll have to modify the function parameter list in the defintion and the values in the scanner_test
}
