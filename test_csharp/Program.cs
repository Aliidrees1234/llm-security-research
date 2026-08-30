using System;
using System.Data.SqlClient;

class Program
{
    static void Main(string[] args)
    {
        string username = Console.ReadLine();
        
        // SQL Injection vulnerability
        string query = "SELECT * FROM users WHERE name = '" + username + "'";
        SqlConnection conn = new SqlConnection("Server=localhost;Database=mydb;");
        SqlCommand cmd = new SqlCommand(query, conn);
        
        // Hardcoded password
        string password = "admin123";
        
        conn.Open();
        cmd.ExecuteReader();
    }
}