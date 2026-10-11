resource "aws_iam_role" "dispatch_quoter" {
  name = "dispatch-quoter-agent-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "bedrock.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "dispatch_quoter" {
  name = "dispatch-quoter-agent-policy"
  role = aws_iam_role.dispatch_quoter.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["bedrock:InvokeModel"]
      Resource = "arn:aws:bedrock:eu-central-1::foundation-model/${var.bedrock_foundation_model}"
    }]
  })
}

resource "aws_bedrockagent_agent" "dispatch_quoter" {
  agent_name                  = "dispatch-quoter"
  agent_resource_role_arn     = aws_iam_role.dispatch_quoter.arn
  foundation_model            = var.bedrock_foundation_model
  idle_session_ttl_in_seconds = 600
  instruction                 = "Quote spot freight requests from the Vantor rate card and escalate quotes above the lane budget to the dispatch desk."

  tags = {
    environment = var.environment
    team        = "freight-desk"
  }
}

resource "aws_lambda_function" "rate_card" {
  function_name = "dispatch-rate-card"
  role          = aws_iam_role.dispatch_quoter.arn
  runtime       = "python3.12"
  handler       = "handler.lookup"
  filename      = "artifacts-rate-card.zip"
}

resource "aws_bedrockagent_agent_action_group" "rate_card" {
  action_group_name = "rate-card-lookup"
  agent_id          = aws_bedrockagent_agent.dispatch_quoter.agent_id
  agent_version     = "DRAFT"

  action_group_executor {
    lambda = aws_lambda_function.rate_card.arn
  }
}

resource "aws_bedrockagent_knowledge_base" "lanes" {
  name     = "lane-history"
  role_arn = aws_iam_role.dispatch_quoter.arn

  knowledge_base_configuration {
    type = "VECTOR"
    vector_knowledge_base_configuration {
      embedding_model_arn = "arn:aws:bedrock:eu-central-1::foundation-model/amazon.titan-embed-text-v2:0"
    }
  }
}
