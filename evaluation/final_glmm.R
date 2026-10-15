# Fixed Phase H backend. Python supplies an explicitly treatment-coded model matrix.
suppressPackageStartupMessages(library(lme4))
suppressPackageStartupMessages(library(jsonlite))
args <- commandArgs(trailingOnly=TRUE)
payload <- fromJSON(args[1], simplifyVector=FALSE)
control <- glmerControl(optimizer="bobyqa", optCtrl=list(maxfun=200000, rhoend=1e-9),
                        calc.derivs=TRUE, check.rankX="stop.deficient")

diagnostics <- function(beta, se, hessian, gradient, converged, variance) {
  # At a zero-variance boundary, the variance coordinate has a constrained optimum;
  # use the fixed-effect block for KKT diagnostics, without rejecting the boundary.
  boundary <- variance < 1e-3
  h <- hessian; g <- gradient
  if (boundary) { h <- h[-1,-1,drop=FALSE]; g <- g[-1] }
  pd <- all(is.finite(h)) && min(eigen(h, symmetric=TRUE, only.values=TRUE)$values) > 0
  scaled <- if (pd) max(abs(solve(chol(h), g))) else Inf
  reasons <- character()
  if (!converged) reasons <- c(reasons, "optimizer or lme4 convergence failure")
  if (!pd) reasons <- c(reasons, "Hessian not positive definite")
  if (!is.finite(scaled) || scaled > 1e-3) reasons <- c(reasons, "scaled gradient exceeds 1e-3")
  if (any(!is.finite(beta)) || any(abs(beta)>10)) reasons <- c(reasons,"coefficient nonfinite or absolute value > 10")
  if (any(!is.finite(se)) || any(se>10)) reasons <- c(reasons,"standard error nonfinite or > 10")
  list(accepted=length(reasons)==0, reasons=as.list(reasons), boundary=boundary,
       random_intercept_variance=variance, hessian_positive_definite=pd,
       max_absolute_scaled_gradient=if(is.finite(scaled)) scaled else NULL)
}

fit_job <- function(job) {
  out <- list(outcome=job$outcome, specification=job$specification, n=length(job$y),
              n_pairs=length(unique(unlist(payload$pair_ids))), accepted=FALSE,
              reasons=list(), coefficients=list(), interactions=list())
  if (!is.null(job$rejection)) { out$reasons <- list(job$rejection); return(out) }
  x <- do.call(rbind,lapply(job$x,unlist))
  columns <- unlist(job$columns)
  # Retain the intercept in x and remove the formula's automatic intercept.
  colnames(x) <- paste0("v",seq_len(ncol(x)))
  dat <- data.frame(y=unlist(job$y), pair_id=factor(unlist(payload$pair_ids)), x)
  formula <- as.formula(paste("y ~ 0 +",paste(colnames(x),collapse=" + "),"+ (1 | pair_id)"))
  warnings <- character()
  fit <- tryCatch(withCallingHandlers(glmer(formula,dat,family=binomial("logit"),nAGQ=30,
                    control=control, na.action=na.fail), warning=function(w) {
                      warnings <<- c(warnings,conditionMessage(w)); invokeRestart("muffleWarning")
                    }), error=function(e) e)
  if (inherits(fit,"error")) {
    numerical <- grepl("converge|PIRLS|pwrssUpdate|positive definite|Cholmod|NaN|non-finite",
                       conditionMessage(fit),ignore.case=TRUE)
    if (!numerical) stop(paste("Unexpected backend error:",conditionMessage(fit)))
    out$reasons <- list(paste("GLMM fitting error:",conditionMessage(fit))); return(out)
  }
  beta <- fixef(fit); covariance <- as.matrix(vcov(fit)); se <- sqrt(diag(covariance))
  messages <- fit@optinfo$conv$lme4$messages
  # Boundary/singularity is reported, not independently rejected.
  messages <- messages[!grepl("boundary.*singular", messages)]
  conv <- all(unlist(fit@optinfo$conv$opt)==0) && length(messages)==0
  diag <- diagnostics(beta,se,fit@optinfo$derivs$Hessian,fit@optinfo$derivs$gradient,
                      conv,as.numeric(VarCorr(fit)$pair_id[1,1]))
  out[names(diag)] <- diag
  out$warnings <- as.list(warnings); out$convergence_messages <- as.list(messages)
  out$log_likelihood <- as.numeric(logLik(fit))
  out$coefficients <- lapply(seq_along(beta),function(i) list(term=columns[i],estimate=unname(beta[i]),
        standard_error=unname(se[i]), odds_ratio=unname(exp(beta[i])),
        odds_ratio_ci_low=unname(exp(beta[i]-qnorm(.975)*se[i])),
        odds_ratio_ci_high=unname(exp(beta[i]+qnorm(.975)*se[i])),
        approximate_wald_p=unname(2*pnorm(-abs(beta[i]/se[i])))))
  for (pattern in c("Optimization.*:Method","Optimization.*:Stripped","Stripped:Method")) {
    indexes <- grep(pattern,columns)
    if(length(indexes) && diag$accepted) {
      b <- beta[indexes]; v <- covariance[indexes,indexes,drop=FALSE]
      statistic <- as.numeric(t(b)%*%solve(v,b))
      out$interactions[[length(out$interactions)+1]] <- list(term=pattern,df=length(indexes),
            statistic=statistic, approximate_wald_p=pchisq(statistic,length(indexes),lower.tail=FALSE))
    }
  }
  out
}

if (isTRUE(payload$self_test)) {
  # Published lme4 cbpp example, distinct from final outcomes.
  fit <- glmer(cbind(incidence,size-incidence) ~ period+(1|herd),cbpp,
               family=binomial,nAGQ=9,control=control)
  stopifnot(max(abs(fixef(fit)-c(-1.3992,-.9914,-1.1278,-1.5795)))<.002)
  # A variance boundary alone is allowed; convergence and Hessian failures reject.
  stopifnot(diagnostics(c(0,1),c(.1,.2),diag(3),c(1,0,0),TRUE,0)$accepted)
  stopifnot(!diagnostics(c(0,1),c(.1,.2),diag(3),c(0,0,0),FALSE,.5)$accepted)
  stopifnot(!diagnostics(c(0,1),c(.1,.2),-diag(3),c(0,0,0),TRUE,.5)$accepted)
  out <- list(self_test=TRUE, cbpp_coefficients=unname(fixef(fit)))
} else {
  out <- list(fits=lapply(payload$jobs,fit_job))
}
out$session_info <- capture.output(sessionInfo())
out$versions <- list(R=as.character(getRversion()),lme4=as.character(packageVersion("lme4")),
                     jsonlite=as.character(packageVersion("jsonlite")))
write_json(out,args[2],auto_unbox=TRUE,pretty=TRUE,digits=16,na="null",null="null")
