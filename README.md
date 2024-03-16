# pwdatav3

-- import "github.com/forsyth/pwdatav3"

Package _pwdatav3_ provides password hashing and verification compatible with ASP.NET Core applications.
It helped me migrate applications from C# to Go, without requiring users to re-register or reset their passwords.
Separately, package _aspnetusers_ supports compatible sharing of the same authentication database.
The two are now separate packages because the Go application might just as well use its own user registration scheme,
while keeping the same password encoding (so users do not need to re-register).
