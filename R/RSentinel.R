library(RCurl)
library(rjson)

connect <- function(
  host = "localhost",
  port = 8443,
  username = NULL,
  password = NULL,
  timeout = 120,
  connecttimeout = 5,
  verbose = TRUE,
  ssl.verifypeer = FALSE,
  ssl.verifyhost= FALSE
  ) {
  
  sentinel <- list(
    #host = host,
    #port = port
    authority = paste("https://", host, ":", port, sep=""),
    baseurl = paste("https://", host, ":", port, "/SentinelRESTServices/objects", sep="")
  )
  
  opts <- curlOptions(
    timeout = timeout,
    connecttimeout = connecttimeout,
    verbose = verbose,
    useragent = "RSentinel/0.1",
    sslversion = SSLVERSION_TLSv1,
    ssl.verifypeer = ssl.verifypeer,
    ssl.verifyhost=ssl.verifyhost,
    customrequest = "GET"
  )
  
  ch <- getCurlHandle()
  
  auth.response<-getURL( 
    paste("https://", host, ":", port, "/SentinelAuthServices/auth/tokens", sep=""),
    customrequest = "POST",
    userpwd = paste(username, password, sep=":"),
    httpauth = AUTH_BASIC,
    .opts = opts, 
    curl = ch 
  )
  
  if (getCurlInfo(ch)$response.code == 201) {
    sentinel$ch <- ch
    sentinel$samlToken <- fromJSON(auth.response)$Token
    sentinel$opts <- curlOptions(
      httpheader = c(
        "Authorization"=paste("X-SAML",sentinel$samlToken, sep=" "),
        "Accept"="application/json",
        "Content-Type"="application/json"
      )
    )
    return(sentinel)
    
  } else {
    return(NA)
  }
}

startEventSearch <- function(sentinel, filter="sev:[0 TO 5]") {
  params <- list(
    "filter"=filter,
    "start"="2014-11-27T20:08:34.940Z",
    "end"  ="2014-11-27T21:08:34.940Z",
    "pgsize"=125,
    "max-results"=50000,
    "type"="user"
  )
  content <- getURL(
    paste(sentinel$baseurl, "event-search", sep="/"),
    customrequest = "POST",
    postfields = toJSON(params),
    .opts = sentinel$opts,
    curl = sentinel$ch
  )
  job <- NULL
  if (getCurlInfo(sentinel$ch)$response.code == 201) {
    job <- fromJSON(content)
  }
  return(job)
}

getEventSearch <- function(sentinel, job) {
  content <- getURL(
    customrequest = "GET",
    #paste(sentinel$authority, job$meta$"@href", sep=""),
    job$meta$"@href",
    .opts = sentinel$opts,
    curl = sentinel$ch
  )
  job <- NULL
  if (getCurlInfo(sentinel$ch)$response.code == 200) {
    print(content)
    job <- fromJSON(content)
  }
  return(job)
}

getEventSearchResults <- function(sentinel, job) {
  response <- getURL(
    customrequest = "GET",
    #paste(sentinel$authority, job$meta$"@href", sep=""),
    job$results$"@href",
    .opts = sentinel$opts,
    curl = sentinel$ch
  )
  objects <- NULL
  if (getCurlInfo(sentinel$ch)$response.code == 200) {
    if (sentinel$verbose) {
      print(response)
    }
    objects <- fromJSON(response)
  }
  return(objects)
}

startSearchTerms <- function(sentinel, job) {
  params <- list(
    "meta"=list("type"="search-terms"),
    "event-search"=list("@href"=job$meta$"@href"),
    "field-names"= list("evt", "sip"),
    "bottom-n" = 1000,
    "top-n" = 1000
  )
  response <- getURL(
    paste("https://", server, ":8443/SentinelRESTServices/objects/search-terms", sep=""),
    customrequest = "POST",
    postfields = toJSON(params),
    .opts = sentinel$opts,
    curl = sentinel$ch
  )
  job <- NULL
  if (getCurlInfo(sentinel$ch)$response.code == 201) {
    job <- fromJSON(response)
  }
  return(job)
}

getSearchTerms <- function(sentinel, job) {
  response <- getURL(
    customrequest = "GET",
    job$meta$"@href",
    .opts = sentinel$opts,
    curl = sentinel$ch
  )
  job <- NULL
  if (getCurlInfo(sentinel$ch)$response.code == 200) {
    print(response)
    job <- fromJSON(response)
  }
  return(job)
}

kvp2df <- function(content) {
  value <- NULL
  count <- NULL

  for (i in 1:length(content$"fields"[[1]]$values)) {
    value <- c(value, content$"fields"[[1]]$values[[i]]$value )
    count <- c(count, content$"fields"[[1]]$values[[i]]$count)
  }
  df = data.frame(value=value,count=count,stringsAsFactors=T)
  return(df)
}

getEpsHistory <- function(sentinel) {
  response <- getURL(
    customrequest = "GET",
    paste(sentinel$baseurl, "eps-history", sep="/"),
    .opts = sentinel$opts,
    curl = sentinel$ch
  )
  result <- NULL
  if (getCurlInfo(sentinel$ch)$response.code == 200) {
    print(response)
    result <- fromJSON(response)
  }
  return(result)
  
}

parseDate <- function(date) {
  return(strptime(d, "%Y-%m-%dT%H:%M:%OS", "UTC"))
}