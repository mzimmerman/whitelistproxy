package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"io"
	"log"
	"os"
	"time"
)

// converts from CSV to the new JSON format
func main() {
	tmp, err := os.Open("whitelist.csv")
	if err != nil {
		log.Fatalf("Error opening csv whitelist - %v", err)
	}
	defer tmp.Close()
	r := csv.NewReader(tmp)
	newFile, err := os.Create("whitelist.json")
	writer := bufio.NewWriter(newFile)
	defer newFile.Close()
	for {
		val, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatalf("Error reading from csv - %v", err)
		}
		t, _ := time.Parse(time.ANSIC, val[4])
		entry := Entry{
			Host:            val[0],
			MatchSubdomains: val[1] == "true",
			Path:            val[2],
			Creator:         val[3],
			Created:         t,
		}
		serialized, err := json.Marshal(entry)
		if err != nil {
			log.Printf("Unable to serialize entry %v - %v", entry, err)
		} else {
			writer.Write(serialized)
			writer.Write([]byte{'\n'})
			writer.Flush()
		}
	}
}

type Entry struct {
	Host            string
	MatchSubdomains bool
	Path            string
	Creator         string
	Created         time.Time
}
