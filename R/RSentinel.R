library(RCurl)
library(rjson)


options(RCurlOptions = list(userpwd = paste(username, password, sep=":"),
                            httpauth = 1L,
                            timeout = 200,
                            connecttimeout = 10,
                            verbose = TRUE,
                            useragent = "RSentinel",
                            sslversion = SSLVERSION_TLSv1,
                            ssl.verifypeer = FALSE,
                            ssl.verifyhost=FALSE))

authJSON<-httpPOST( paste("https://", server, ":8443/SentinelAuthServices/auth/tokens", sep="") )

samlToken <- fromJSON(authJSON)$Token
authorization <- paste("X-SAML",samlToken, sep=" ")

collectorJSON <-  httpGET(
  paste("https://", server, ":8443/SentinelRESTServices/objects/collector", sep=""),
  httpheader = c(
    "Authorization"=authorization
  )
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

epsJSON <-  httpGET(
  paste("https://", server, ":8443/SentinelRESTServices/objects/eps-history", sep=""),
  httpheader = c(
    "Authorization"=authorization
  ), verbose = F
)
