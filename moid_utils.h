/*
Copyright (C) 2007-2010 Butterfat, LLC (http://butterfat.net)

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

Created by bmuller <bmuller@butterfat.net>
*/

namespace modauthopenid {
  using namespace opkele;
  using namespace std;

  // get the appropriate error string for the given error
  string error_to_string(error_result_t e, bool use_short_string);

  // explode string s into parts, split based on occurance of e
  vector<string> explode(string s, string e);

  // replace needle with replacement in haystack
  string str_replace(string needle, string replacement, string haystack);

  // Should be using ap_log_error, but that would mean passing a server_rec* or request_rec* around..... 
  // gag....  I'm just assuming that if you're going to be debugging it shouldn't really matter, since
  // apache redirects stderr to the error log anyway.
  void debug(string s);

  // print a string to the error log (called by debug if DEBUG is defined)
  void print_to_error_log(string s);

  // return true if pattern found in subject
  bool regex_match(string subject, string pattern);

  // strip any spaces before or after actual string in s
  void strip(string& s);

  // make a random string of size size
  void make_rstring(int size, string& s);

  // Exec a program located at exec_location with a single parameter of username
  // program should return a 0 if authorized, anything else otherwise
  // NOTE: if program hangs, so does apache
  bool exec_auth(string exec_location, string username);

  // Generate a random integer - taken from getuuid.c file in apr-util program
  int true_random();
}

