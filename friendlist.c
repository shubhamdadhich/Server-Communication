/*
 * friendlist.c - A web-based friend-graph manager.
 *
 * Based on:
 *  tiny.c - A simple, iterative HTTP/1.0 Web server that uses the 
 *      GET method to serve static and dynamic content.
 *   Tiny Web server
 *   Dave O'Hallaron
 *   Carnegie Mellon University
 */
#include "csapp.h"
#include "dictionary.h"
#include "more_string.h"

static void* thread_doit(void *_fd);
static void doit(int fd);
static dictionary_t *read_hdrs(rio_t *rp);
static void read_postquery(rio_t *rp, dictionary_t *headers, dictionary_t *d);
static void clienterror(int fd, char *cause, char *errnum, 
                        char *shortmsg, char *longmsg);
static void print_stringdictionary(dictionary_t *d);

static void serve_friends(int fd, dictionary_t *query);
static void serve_befriend(int fd, dictionary_t *query);
static void serve_unfriend(int fd, dictionary_t *query);
static void serve_introduce(int fd, dictionary_t *query);

static dictionary_t *friend_lists;
static sem_t lists_sem;

int main(int argc, char **argv) 
{
  int listenfd, connfd, *connfdp;
  char hostname[MAXLINE], port[MAXLINE];
  socklen_t clientlen;
  struct sockaddr_storage clientaddr;
  pthread_t tid;

  /* Check command line args */
  if (argc != 2) {
    fprintf(stderr, "usage: %s <port>\n", argv[0]);
    exit(1);
  }

  friend_lists = make_dictionary(COMPARE_CASE_SENS, (free_proc_t)free_dictionary);

  Sem_init(&lists_sem, 0, 1);

  listenfd = Open_listenfd(argv[1]);

  /* Don't kill the server if there's an error, because
     we want to survive errors due to a client. But we
     do want to report errors. */
  exit_on_error(0);

  /* Also, don't stop on broken connections: */
  Signal(SIGPIPE, SIG_IGN);

  while (1) {
    clientlen = sizeof(clientaddr);
    connfd = Accept(listenfd, (SA *)&clientaddr, &clientlen);
    if (connfd >= 0) {
      Getnameinfo((SA *) &clientaddr, clientlen, hostname, MAXLINE, 
                  port, MAXLINE, 0);
      printf("Accepted connection from (%s, %s)\n", hostname, port);
      
      connfdp = malloc(sizeof(connfd));
      *connfdp = connfd;

      // non-concurrent version
//      doit(*connfdp);
//      Close(*connfdp);

      Pthread_create(&tid, NULL, thread_doit, connfdp);
      Pthread_detach(tid);
    }
  }
}

void *thread_doit(void *_fd) {
  int fd = *(int *)_fd;
  free(_fd);

  doit(fd);

  Close(fd);
  
  return NULL;
}

/*
 * doit - handle one HTTP request/response transaction
 */
void doit(int fd)
{
  char buf[MAXLINE], *method, *uri, *version;
  rio_t rio;
  dictionary_t *headers, *query;

  /* Read request line and headers */
  Rio_readinitb(&rio, fd);
  if (Rio_readlineb(&rio, buf, MAXLINE) <= 0)
    return;
  printf("%s", buf);
  if (!parse_request_line(buf, &method, &uri, &version)) {
    clienterror(fd, method, "400", "Bad Request",
                "Friendlist did not recognize the request");
  } else {
    if (strcasecmp(version, "HTTP/1.0")
        && strcasecmp(version, "HTTP/1.1")) {
      clienterror(fd, version, "501", "Not Implemented",
                  "Friendlist does not implement that version");
    } else if (strcasecmp(method, "GET")
               && strcasecmp(method, "POST")) {
      clienterror(fd, method, "501", "Not Implemented",
                  "Friendlist does not implement that method");
    } else {
      headers = read_hdrs(&rio);

      /* Parse all query arguments into a dictionary */
      query = make_dictionary(COMPARE_CASE_SENS, free);
      parse_uriquery(uri, query);
      if (!strcasecmp(method, "POST"))
        read_postquery(&rio, headers, query);

      /* For debugging, print the dictionary */
      print_stringdictionary(query);

      if (starts_with("/befriend", uri))
        serve_befriend(fd, query);
      else if (starts_with("/unfriend", uri))
        serve_unfriend(fd, query);
      else if (starts_with("/introduce", uri))
        serve_introduce(fd, query);
      else
        serve_friends(fd, query);

      /* Clean up */
      free_dictionary(query);
      free_dictionary(headers);
    }

    /* Clean up status line */
    free(method);
    free(uri);
    free(version);
  }
}

/*
 * read_thdrs - read HTTP request or response headers
 */
dictionary_t *read_hdrs(rio_t *rp) 
{
  char buf[MAXLINE];
  dictionary_t *d = make_dictionary(COMPARE_CASE_INSENS, free);

  Rio_readlineb(rp, buf, MAXLINE);
  printf("%s", buf);
  while(strcmp(buf, "\r\n")) {
    Rio_readlineb(rp, buf, MAXLINE);
    printf("%s", buf);
    parse_header_line(buf, d);
  }
  
  return d;
}

void read_postquery(rio_t *rp, dictionary_t *headers, dictionary_t *dest)
{
  char *len_str, *type, *buffer;
  int len;
  
  len_str = dictionary_get(headers, "Content-Length");
  len = (len_str ? atoi(len_str) : 0);

  type = dictionary_get(headers, "Content-Type");
  
  buffer = malloc(len+1);
  Rio_readnb(rp, buffer, len);
  buffer[len] = 0;

  if (!strcasecmp(type, "application/x-www-form-urlencoded")) {
    parse_query(buffer, dest);
  }

  free(buffer);
}

static char *ok_header(size_t len, const char *content_type) {
  char *len_str, *header;
  
  header = append_strings("HTTP/1.0 200 OK\r\n",
                          "Server: Friendlist Web Server\r\n",
                          "Connection: close\r\n",
                          "Content-length: ", len_str = to_string(len), "\r\n",
                          "Content-type: ", content_type, "\r\n\r\n",
                          NULL);
  free(len_str);

  return header;
}

static void add_friend(const char *user, const char *friend) {
  /* assumes that lock is held */
  dictionary_t *friend_list;
  
  friend_list = dictionary_get(friend_lists, user);

  if (!friend_list) {
    friend_list = make_dictionary(COMPARE_CASE_SENS, NULL);
    dictionary_set(friend_lists, user, friend_list);
  }

  dictionary_set(friend_list, friend, NULL);
}

static void add_friends(const char *user, const char *content) {
  char **friends = split_string(content, '\n');
  int i;

  for (i = 0; friends[i] != NULL; i++) {
    if (strcmp(friends[i], user)) {
      add_friend(user, friends[i]);
      add_friend(friends[i], user);
    }
    free(friends[i]);
  }

  free(friends);
}

static void remove_friend(const char *user, const char *friend) {
  /* assumes that lock is held */
  dictionary_t *friend_list;
  
  friend_list = dictionary_get(friend_lists, user);

  if (friend_list)
    dictionary_remove(friend_list, friend);
}

static void remove_friends(const char *user, const char *content) {
  char **friends = split_string(content, '\n');
  int i;

  for (i = 0; friends[i] != NULL; i++) {
    remove_friend(user, friends[i]);
    remove_friend(friends[i], user);
    free(friends[i]);
  }

  free(friends);
}

char *get_friends(const char *user) {
  /* assumes that lock is held */
  dictionary_t *friend_list;
  char *friends;
  
  friend_list = dictionary_get(friend_lists, user);

  if (friend_list) {
    const char **friend_array = dictionary_keys(friend_list);
    friends = join_strings(friend_array, '\n');
    free(friend_array);
  } else {
    friends = strdup("");
  }

  return friends;
}

void serve_friends(int fd, dictionary_t *query)
{
  char *user = dictionary_get(query, "user");
  char *content;
  char *header;
  size_t len;

  if (!user) {
    clienterror(fd, "user", "400", "Bad Request",
                "Missing a user");
    return;
  }

  P(&lists_sem);
  content = get_friends(user);
  V(&lists_sem);

  len = strlen(content);
  
  header = ok_header(len, "text/plain; charset=utf-8");
  Rio_writen(fd, header, strlen(header));
  free(header);

  if (len)
    Rio_writen(fd, content, len);
  free(content);
}

void serve_befriend(int fd, dictionary_t *query)
{
  char *user = dictionary_get(query, "user");
  char *friends = dictionary_get(query, "friends");

  if (!user) {
    clienterror(fd, "befriend", "400", "Bad Request",
                "Missing a user");
    return;
  }
  if (!friends) {
    clienterror(fd, "befriend", "400", "Bad Request",
                "Missing friends");
    return;
  }

  P(&lists_sem);
  add_friends(user, friends);
  V(&lists_sem);

  serve_friends(fd, query);
}

void serve_unfriend(int fd, dictionary_t *query)
{
  char *user = dictionary_get(query, "user");
  char *friends = dictionary_get(query, "friends");

  if (!user) {
    clienterror(fd, "say", "400", "Bad Request",
                "Missing a user");
    return;
  }
  if (!friends) {
    clienterror(fd, "unfriend", "400", "Bad Request",
                "Missing friends");
    return;
  }

  P(&lists_sem);
  remove_friends(user, friends);
  V(&lists_sem);

  serve_friends(fd, query);
}

void serve_introduce(int fd, dictionary_t *query)
{
  char *user = dictionary_get(query, "user");
  char *friend = dictionary_get(query, "friend"), *friend_e;
  char *host = dictionary_get(query, "host");
  char *port = dictionary_get(query, "port");
  char buf[MAXLINE];
  char *version, *status;
  char *request, *content, *header;
  const char *content_len;
  dictionary_t *headers;
  size_t len, amt;
  rio_t rio;
  int from_fd;

  if (!user) {
    clienterror(fd, "user", "400", "Bad Request",
                "Missing a topic");
    return;
  }
  if (!friend) {
    clienterror(fd, "user", "400", "Bad Request",
                "Missing a friend");
    return;
  }
  if (!host) {
    clienterror(fd, "import", "400", "Bad Request",
                "Missing a host");
    return;
  }
  if (!port) {
    clienterror(fd, "import", "400", "Bad Request",
                "Missing a port");
    return;
  }

  friend_e = query_encode(friend);
  request = append_strings("GET /friends?user=", friend_e,
                           " HTTP/1.0\r\n",
                           "\r\n",
                           NULL);
  free(friend_e);
  
  from_fd = Open_clientfd(host, port);

  Rio_writen(from_fd, request, strlen(request));
  free(request);

  Rio_readinitb(&rio, from_fd);
  if (Rio_readlineb(&rio, buf, MAXLINE) <= 0) {
    clienterror(fd, "introduce", "500", "Internal Server Error",
                "No status line from other server");
  } else {
    if (!parse_status_line(buf, &version, &status, NULL)) {
      clienterror(fd, "introduce", "500", "Internal Server Error",
                  "Bad status line from other server");
    } else {
      if (strcmp(version, "HTTP/1.0")) {
        clienterror(fd, status, "500", "Internal Server Error",
                    "Bad version from other server");
      } else if (strcmp(status, "200")) {
        clienterror(fd, status, "500", "Internal Server Error",
                    "Non-success status from other server");
      } else {
        headers = read_hdrs(&rio);

        content_len = dictionary_get(headers, "content-length");
        if (!content_len) {
          clienterror(fd, "introduce", "500", "Internal Server Error",
                      "No content-length from other server");
        } else {
          len = atol(content_len);

          content = malloc(len+1);
          amt = Rio_readnb(&rio, content, len);
          content[len] = 0;

          if (amt != len)  {
            clienterror(fd, "introduce", "500", "Internal Server Error",
                        "Truncated response from other server");
          } else {
            P(&lists_sem);
            add_friends(user, content);
            add_friend(user, friend);
            add_friend(friend, user);
            V(&lists_sem);

            header = ok_header(0, "text/plain");
            Rio_writen(fd, header, strlen(header));
            free(header);
          }

          free(content);
        }
      
        free_dictionary(headers);
      }
    
      free(version);
      free(status);
    }
  }
  Close(from_fd);
}

/*
 * clienterror - returns an error message to the client
 */
void clienterror(int fd, char *cause, char *errnum, 
		 char *shortmsg, char *longmsg) 
{
  size_t len;
  char *header, *body, *len_str;

  body = append_strings("<html><title>Friendlist Error</title>",
                        "<body bgcolor=""ffffff"">\r\n",
                        errnum, " ", shortmsg,
                        "<p>", longmsg, ": ", cause,
                        "<hr><em>Friendlist Server</em>\r\n",
                        NULL);
  len = strlen(body);

  /* Print the HTTP response */
  header = append_strings("HTTP/1.0 ", errnum, " ", shortmsg, "\r\n",
                          "Content-type: text/html; charset=utf-8\r\n",
                          "Content-length: ", len_str = to_string(len), "\r\n\r\n",
                          NULL);
  free(len_str);
  
  Rio_writen(fd, header, strlen(header));
  Rio_writen(fd, body, len);

  free(header);
  free(body);
}

static void print_stringdictionary(dictionary_t *d)
{
  int i, count;

  count = dictionary_count(d);
  for (i = 0; i < count; i++) {
    printf("%s=%s\n",
           dictionary_key(d, i),
           (const char *)dictionary_value(d, i));
  }
  printf("\n");
}


