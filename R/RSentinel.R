library(RCurl)
library(rjson)


opts <- curlOptions(
  timeout = 120,
  connecttimeout = 5,
  verbose = TRUE,
  useragent = "RSentinel/0.1",
  sslversion = SSLVERSION_TLSv1,
  ssl.verifypeer = FALSE,
  ssl.verifyhost=FALSE,
  customrequest = "GET"
)

ch <- getCurlHandle()

authJSON<-getURL( 
  paste("https://", server, ":8443/SentinelAuthServices/auth/tokens", sep=""),
  customrequest = "POST",
  userpwd = paste(username, password, sep=":"),
  httpauth = AUTH_BASIC,
  .opts = opts, 
  curl = ch 
)

samlToken <- fromJSON(authJSON)$Token
authorization <- paste("X-SAML",samlToken, sep=" ")

opts <- curlOptions(
  httpheader = c(
    "Authorization"=authorization,
    "Accept"="application/json"#,
    #"Content-Type"="application/json"
  )
)

opts.post <- curlOptions(
  httpheader = c(
    opts$httpheader,
    "Content-Type"="application/json"
  )
)


collectorJSON <-  getURL(
  paste("https://", server, ":8443/SentinelRESTServices/objects/collector", sep=""),
  customrequest = "GET",
  #httpheader = c( "Authorization"=authorization)
  .opts = opts,
  curl = ch
)

getCollectorDataframeFromJSON <- function(collectorJSON) {
  namelist <- NULL
  urllist <- NULL
  statuslist <- NULL
  datelist <- NULL
  JSONList <- fromJSON(collectorJSON)
  results <- JSONList$objects
  for (i in 1:length(results)) {
    namelist <- c(namelist, results[i][[1]]$name )
    urllist <- c(urllist, results[i][[1]]$meta$"@href")
    onlist <- c(statuslist, results[i][[1]]$on)
    pluginlist <- c(datelist, results[i][[1]]$plugin)
  }
  collectorDF = data.frame(name=namelist,href=urllist,on=onlist,plugin=pluginlist,stringsAsFactors=T)
  return(collectorDF)
}

cdf <- getCollectorDataframeFromJSON(collectorJSON)

epsJSON <- getURL(
  paste("https://", server, ":8443/SentinelRESTServices/objects/eps-history", sep=""),
  customrequest = "GET",
  .opts = opts,
  curl = ch
)

createSearchJob <- function(filter) {
  params <- list(
    "filter"=filter,
    "start"="2014-11-27T20:08:34.940Z",
    "end"  ="2014-11-27T21:08:34.940Z",
    "pgsize"=125,
    "max-results"=50000,
    "type"="user"
  )
  content <- getURL(
    paste("https://", server, ":8443/SentinelRESTServices/objects/event-search", sep=""),
    customrequest = "POST",
    postfields = toJSON(params),
    #httpheader = c( "Content-Type"="application/json", opts$httpheader),
    .opts = opts.post,
    curl = ch
  )
  job <- NULL
  if (getCurlInfo(ch)$response.code == 201) {
    job <- fromJSON(content)
  }
  return(job)
}

createSearchTermJob <- function(job) {
  params <- list(
    "meta"=list("type"="search-terms"),
    "event-search"=list("@href"=job$meta$"@href"),
    "field-names"= list("evt", "sip")
  )
  content <- getURL(
    paste("https://", server, ":8443/SentinelRESTServices/objects/search-terms", sep=""),
    customrequest = "POST",
    postfields = toJSON(params),
    #httpheader = c( "Content-Type"="application/json", opts$httpheader),
    .opts = opts.post,
    curl = ch
  )
  job <- NULL
  if (getCurlInfo(ch)$response.code == 201) {
    job <- fromJSON(content)
  }
  return(job)
}


